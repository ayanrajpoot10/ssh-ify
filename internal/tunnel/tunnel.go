// Package tunnel implements the proxy server and connection handling logic for ssh-ify.
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

	"github.com/ayanrajpoot10/ssh-ify/internal/ssh"
	"github.com/ayanrajpoot10/ssh-ify/pkg/certgen"
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

// CopyWithBuffer performs buffered copying using a pooled buffer.
func CopyWithBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := getBuffer()
	defer putBuffer(buf)
	return io.CopyBuffer(dst, src, *buf)
}

// Server manages TCP and TLS connections for the ssh-ify tunnel proxy server.
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
type Session struct {
	client    net.Conn
	target    net.Conn
	server    *Server
	sshConfig *ssh.ServerConfig
	sessionID string
}

// Server methods
// Add registers a new client connection with the server.
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

// Remove unregisters a client connection from the server.
func (s *Server) Remove(conn *Session) {
	s.conns.Delete(conn)
	s.wg.Done()
	newCount := atomic.AddInt32(&s.activeCount, -1)
	log.Println("Connection removed. Active:", newCount)
}

// Shutdown gracefully terminates the server.
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

// NewServer constructs and returns a new Server with default configuration.
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

// ListenAndServe starts both TCP and TLS tunnel servers simultaneously.
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
// Close safely closes both client and target connections.
func (s *Session) Close() {
	if s.client != nil {
		s.client.Close()
	}
	if s.target != nil {
		s.target.Close()
	}
}

// Handle manages the lifecycle of a client connection.
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

// Relay copies data bidirectionally between client and target connections.
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
// HeaderValue extracts the value of a specific HTTP header from header lines.
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
// WebSocketHandler upgrades a session to WebSocket and establishes an SSH tunnel.
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
