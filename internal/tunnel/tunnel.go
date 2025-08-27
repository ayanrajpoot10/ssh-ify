// Package tunnel implements the proxy server and connection handling logic for ssh-ify.
//
// Features:
//   - Manages incoming TCP and TLS connections for HTTP, WebSocket, and SSH tunneling
//   - Handles protocol upgrades, including WebSocket and HTTP CONNECT
//   - Provides in-process SSH server integration for secure tunnels
//   - Tracks and manages active client connections with concurrency safety
//   - Supports graceful shutdown and connection cleanup
//   - Includes utility functions and constants for buffer sizes, timeouts, and HTTP responses
//   - Optimized I/O operations with reusable buffer pools for better performance
//
// Usage:
//  1. Create a new Server with NewServer
//  2. Start the server using ListenAndServe (for TCP) and ListenAndServeTLS (for TLS)
//  3. Each incoming connection is handled by a Session, which manages protocol upgrades and relays data
//  4. Utility functions and constants are available for request parsing and configuration
//  5. High-performance I/O operations use reusable buffers to reduce allocations
//
// This package is intended for use by the ssh-ify proxy server and related internal components.
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ssh-ify/internal/ssh"
	"ssh-ify/pkg/certgen"
)

// Constants
const (
	// BufferPoolSize is the size of each buffer in the pool (32KB)
	BufferPoolSize = 32 * 1024

	// BufferSize defines the buffer size (in bytes) for reading client requests.
	BufferSize = 4096 * 4

	// ClientReadTimeout specifies the maximum duration to wait for client data before timing out.
	ClientReadTimeout = 60 * time.Second

	// WebSocketUpgradeResponse is the HTTP response sent to clients to acknowledge a successful
	// WebSocket protocol upgrade. This is used to establish SSH-over-WebSocket tunnels.
	WebSocketUpgradeResponse = "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
)

// Default configuration values
var (
	// DefaultListenAddress is the default address the proxy server listens on (all interfaces).
	DefaultListenAddress string = "0.0.0.0"

	// DefaultListenPort is the default port the proxy server listens on (HTTP/WS).
	DefaultListenPort int = 80

	// DefaultListenTLSPort is the default TLS listen port (HTTPS).
	DefaultListenTLSPort int = 443

	// bufferPool is a pool of reusable byte slices for I/O operations
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, BufferPoolSize)
			return &buf
		},
	}
)

// Buffer pool functions
// getBuffer retrieves a buffer from the pool
func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// putBuffer returns a buffer to the pool for reuse
func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

// CopyWithBuffer performs buffered copying between src and dst using a pooled buffer.
// It's more efficient than io.Copy for high-frequency operations as it reuses buffers
// and reduces garbage collection pressure.
//
// Parameters:
//   - dst: The destination writer
//   - src: The source reader
//
// Returns:
//   - int64: The number of bytes copied
//   - error: Any error that occurred during copying
func CopyWithBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := getBuffer()
	defer putBuffer(buf)
	return io.CopyBuffer(dst, src, *buf)
}

// Server manages all incoming TCP and TLS connections for the ssh-ify tunnel proxy server.
//
// Server tracks active client connections and ensures thread-safe operations using sync primitives.
// It supports both plain TCP and TLS (HTTPS/WebSocket) connections and provides methods for graceful startup and shutdown.
//
// Fields:
//   - host:        Listen address
//   - tcpPort:     Listen port for plain TCP/WS
//   - tlsPort:     Listen port for TLS/HTTPS
//   - ctx:         Context for cancellation
//   - cancel:      Cancel function for context
//   - conns:       Map of active sessions (concurrency safe)
//   - activeCount: Atomic counter for active connections
//   - tlsCertFile: Path to TLS certificate file
//   - tlsKeyFile:  Path to TLS key file
//   - wg:          WaitGroup to track active sessions
type Server struct {
	host        string
	tcpPort     int
	tlsPort     int
	ctx         context.Context
	cancel      context.CancelFunc
	conns       sync.Map       // map[*Session]struct{} for concurrency safety
	activeCount int32          // atomic counter for active connections
	tlsCertFile string         // Path to TLS certificate file
	tlsKeyFile  string         // Path to TLS key file
	wg          sync.WaitGroup // WaitGroup to track active sessions
}

// Session manages a single client connection for the ssh-ify tunnel proxy server.
//
// Session encapsulates the state and logic for handling a client session, including
// protocol upgrades (WebSocket/SSH), bidirectional data relay, and connection cleanup.
// Each Session is associated with a parent Server and maintains references to both
// the client and target connections.
//
// Fields:
//   - client:    The client network connection
//   - target:    The target network connection (after upgrade)
//   - server:    The parent Server
//   - sshConfig: SSH server configuration for this session
//   - sessionID: Unique identifier for the session
type Session struct {
	client    net.Conn
	target    net.Conn
	server    *Server
	sshConfig *ssh.ServerConfig
	sessionID string
}

// Server methods
// Add registers a new client connection with the server's active connection map.
//
// This method is concurrency-safe and increments the active connection count.
// It is typically called after successful authentication or tunnel establishment.
//
// Example:
//
//	server.Add(session)
func (s *Server) Add(conn *Session) {
	select {
	case <-s.ctx.Done():
		return
	default:
		s.conns.Store(conn, struct{}{})
		s.wg.Add(1)
		newCount := atomic.AddInt32(&s.activeCount, 1)
		log.Println("Connection added. Active:", newCount)
	}
}

// Remove unregisters a client connection from the server's active connection map.
//
// This method is concurrency-safe and decrements the active connection count.
// It should be called when a connection is closed or cleaned up.
//
// Example:
//
//	server.Remove(session)
func (s *Server) Remove(conn *Session) {
	s.conns.Delete(conn)
	s.wg.Done()
	newCount := atomic.AddInt32(&s.activeCount, -1)
	log.Println("Connection removed. Active:", newCount)
}

// Shutdown gracefully terminates the server by closing all active sessions and
// waiting for all ongoing operations to complete. It logs the shutdown process
// and ensures that all resources are properly released before returning.
//
// Example:
//
//	server.Shutdown()
func (s *Server) Shutdown() {
	log.Println("Closing all active connections...")
	s.conns.Range(func(key, value any) bool {
		if sess, ok := key.(*Session); ok {
			sess.Close()
		}
		return true
	})
	s.wg.Wait()
	log.Println("All sessions closed.")
}

// NewServer constructs and returns a new Server with default configuration values.
//
// The returned server is ready to accept connections on the default address and port.
//
// Example:
//
//	server := tunnel.NewServer()
func NewServer() *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		host:        DefaultListenAddress,
		tcpPort:     DefaultListenPort,
		tlsPort:     DefaultListenTLSPort,
		ctx:         ctx,
		cancel:      cancel,
		conns:       sync.Map{},
		tlsCertFile: "cert.pem",
		tlsKeyFile:  "key.pem",
	}
}

// StartServer launches the tunnel proxy server and manages its lifecycle.
//
// This function sets up signal handling for graceful shutdown and starts both TCP and TLS
// servers simultaneously in separate goroutines. It blocks until a shutdown signal is received,
// then stops the server and logs the shutdown event.
//
// Example:
//
//	tunnel.StartServer()
func StartServer() {
	s := NewServer()

	// Create a channel to receive OS signals for graceful shutdown.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Start both TCP and TLS servers simultaneously in separate goroutines.
	s.ListenAndServe()

	// Block until a shutdown signal is received (e.g., Ctrl+C or SIGTERM).
	<-c
	// Signal received: stop the server and log shutdown.
	s.cancel()
	s.Shutdown()
	log.Println("Shutting down...")
}

// Listen and serve methods
// serveListener continuously accepts incoming connections on the provided listener and
// spawns a new session for each connection. It monitors the server context for shutdown
// signals and ensures proper handling of connection deadlines and errors.
func serveListener(s *Server, ln net.Listener) {
	defer ln.Close()
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Set deadline for TCPListener if possible
			if tcpLn, ok := ln.(*net.TCPListener); ok {
				tcpLn.SetDeadline(time.Now().Add(2 * time.Second))
			}
			conn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			sess := &Session{client: conn, server: s, sessionID: conn.RemoteAddr().String()}
			go sess.Handle()
		}
	}
}

// ListenAndServe starts both TCP and TLS tunnel servers simultaneously in separate goroutines.
//
// It starts a plain TCP listener on the configured host and port, and a TLS listener on port 443.
// Both listeners run concurrently and handle incoming connections independently.
//
// Example:
//
//	server.ListenAndServe()
func (s *Server) ListenAndServe() {
	// Start TCP listener in a goroutine
	go s.listenTCP()

	// Start TLS listener in a goroutine
	go s.listenTLS()
}

// listenTCP starts the plain TCP listener and handles incoming connections.
func (s *Server) listenTCP() {
	addr := fmt.Sprintf("%s:%d", s.host, s.tcpPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on TCP %s: %v", addr, err)
	}
	log.Printf("TCP server listening on %s", addr)
	serveListener(s, ln)
}

// listenTLS starts the TLS listener and handles incoming secure connections.
func (s *Server) listenTLS() {
	// Auto-generate certificates if they don't exist
	if err := certgen.GenerateCert(s.tlsCertFile, s.tlsKeyFile); err != nil {
		log.Fatalf("Failed to generate TLS certificates: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate or key: %v", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	addr := fmt.Sprintf("%s:%d", s.host, s.tlsPort)

	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on TLS %s: %v", addr, err)
	}

	ln := tls.NewListener(tcpLn, tlsConfig)
	log.Printf("TLS server listening on %s", addr)
	serveListener(s, ln)
}

// Session methods
// Close safely closes both the client and target connections managed by this Session.
//
// This method is idempotent and ensures that resources are released only once.
//
// Example:
//
//	session.Close()
func (s *Session) Close() {
	if s.client != nil {
		s.client.Close()
	}
	if s.target != nil {
		s.target.Close()
	}
}

// Handle manages the lifecycle of a client connection from initial request to tunnel establishment.
//
// It parses the HTTP request, detects protocol upgrades (WebSocket/SSH), initializes the SSH server
// configuration if needed, and establishes the tunnel. All major events and errors are logged for auditing.
//
// Example:
//
//	sess.Handle()
func (s *Session) Handle() {
	log.Printf("[session %s] New connection opened", s.sessionID)

	// Set a read deadline to avoid hanging connections.
	s.client.SetReadDeadline(time.Now().Add(ClientReadTimeout))
	reader := bufio.NewReaderSize(s.client, BufferSize)
	var builder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[session %s] Error reading from client: %v", s.sessionID, err)
			log.Printf("[session %s] Closing connection due to read error.", s.sessionID)
			return
		}
		builder.WriteString(line)
		if strings.HasSuffix(builder.String(), "\r\n\r\n") {
			break
		}
		// Prevent header overflow attacks.
		if builder.Len() > BufferSize {
			log.Printf("[session %s] Header too large, closing connection", s.sessionID)
			s.client.Write([]byte("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"))
			return
		}
	}
	buf := builder.String()

	reqLines := strings.Split(buf, "\r\n")
	if len(reqLines) > 0 {
		log.Printf("[session %s] Request received: %s", s.sessionID, reqLines[0])
		hostHeader := HeaderValue(reqLines[1:], "Host")
		if hostHeader != "" {
			log.Printf("[session %s] Host header: %s", s.sessionID, hostHeader)
		}
		cfIP := HeaderValue(reqLines[1:], "CF-Connecting-IP")
		if cfIP != "" {
			log.Printf("[session %s] CF-Connecting-IP header: %s", s.sessionID, cfIP)
		}
	}

	// Remove read deadline for rest of session.
	s.client.SetReadDeadline(time.Time{})

	// Handle WebSocket upgrade and tunnel setup using the new handler.
	if WebSocketHandler(s, reqLines[1:]) {
		s.Relay()
	}
}

// Relay copies data bidirectionally between the client and target connections using goroutines.
//
// This method ensures proper cleanup after data transfer is complete, including closing connections
// and removing the Session from the server's active connection map. It is safe to call multiple times.
//
// Example:
//
//	sess.Relay()
func (s *Session) Relay() {
	defer func() {
		s.Close()          // Clean up both connections
		s.server.Remove(s) // Remove from active map
		log.Printf("[session %s] Connection closed.", s.sessionID)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client → target
	go func() {
		defer wg.Done()
		_, err := CopyWithBuffer(s.target, s.client)
		if err != nil && !isIgnorableError(err) {
			log.Printf("[session %s] Error copying client to target: %v", s.sessionID, err)
		}
		// Important: Closing target to unblock other io.Copy
		s.target.Close()
	}()

	// Copy target → client
	go func() {
		defer wg.Done()
		_, err := CopyWithBuffer(s.client, s.target)
		if err != nil && !isIgnorableError(err) {
			log.Printf("[session %s] Error copying target to client: %v", s.sessionID, err)
		}
		// Important: Closing client to unblock other io.Copy
		s.client.Close()
	}()

	wg.Wait()
}

// Utility functions
// HeaderValue extracts the value of a specific HTTP header from a slice of header lines.
//
// It performs a case-insensitive search for the header name and returns the value if found, or an empty string otherwise.
// This utility is used for parsing incoming client requests and extracting metadata such as Host or custom headers.
//
// Parameters:
//   - headers: Slice of header lines (e.g., from strings.Split(request, "\r\n")).
//   - headerName: The name of the header to extract (case-insensitive).
//
// Returns:
//   - string: The value of the header, or "" if not found.
//
// Example:
//
//	host := tunnel.HeaderValue(headers, "Host")
func HeaderValue(headers []string, headerName string) string {
	headerNameLower := strings.ToLower(headerName)
	for _, line := range headers {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(parts[0])) == headerNameLower {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

// isIgnorableError returns true if the error is EOF or a known benign network error.
//
// Used internally to suppress logging for expected connection closure errors.
func isIgnorableError(err error) bool {
	if err == io.EOF {
		return true
	}
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection")
}

// WebSocket handling
// WebSocketHandler upgrades an incoming session to a WebSocket connection and establishes
// a tunnel using an in-process SSH server. It validates the Upgrade header, initializes
// the SSH configuration if necessary, and sets up a bidirectional proxy between the client
// and the SSH server.
//
// Returns true if the upgrade and tunnel setup succeed, or false on failure.
//
// Parameters:
//   - s:        The Session to upgrade.
//   - reqLines: The HTTP request lines from the client.
//
// Example:
//
//	ok := tunnel.WebSocketHandler(session, reqLines)
func WebSocketHandler(s *Session, reqLines []string) bool {
	upgradeHeader := HeaderValue(reqLines, "Upgrade")

	if upgradeHeader == "" {
		log.Printf("[session %s] No Upgrade header found. Closing connection.", s.sessionID)
		s.Close()
		return false
	}

	log.Printf("[session %s] WebSocket upgrade: using in-process SSH server.", s.sessionID)
	proxyEnd, sshEnd := net.Pipe()
	if s.sshConfig == nil {
		var err error
		s.sshConfig, err = ssh.NewConfig()
		if err != nil {
			log.Printf("[session %s] Error initializing SSH config: %v", s.sessionID, err)
			return false
		}
	}
	go ssh.HandleSSHConnection(sshEnd, s.sshConfig, func() {
		s.server.Add(s)
	})
	s.target = proxyEnd
	if _, err := s.client.Write([]byte(WebSocketUpgradeResponse)); err != nil {
		log.Printf("[session %s] Failed to write WebSocket upgrade response: %v", s.sessionID, err)
		s.Close()
		return false
	}
	log.Printf("[session %s] Tunnel established.", s.sessionID)
	return true
}
