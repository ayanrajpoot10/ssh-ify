package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ssh-ify/pkg/certgen"
)

// Server manages all incoming TCP and TLS connections for the ssh-ify tunnel proxy server.
//
// It tracks active client connections and ensures thread-safe operations using sync
// primitives. The server supports both plain TCP and TLS (HTTPS/WebSocket) connections
// and provides methods for graceful startup and shutdown.
type Server struct {
	host        string
	port        int
	ctx         context.Context
	cancel      context.CancelFunc
	conns       sync.Map       // map[*Session]struct{} for concurrency safety
	activeCount int32          // atomic counter for active connections
	tlsCertFile string         // Path to TLS certificate file
	tlsKeyFile  string         // Path to TLS key file
	wg          sync.WaitGroup // WaitGroup to track active sessions
}

// Add registers a new client connection with the server's active connection map.
//
// This method is concurrency-safe and increments the active connection count.
// It is typically called after successful authentication or tunnel establishment.
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
func (s *Server) Remove(conn *Session) {
	s.conns.Delete(conn)
	s.wg.Done()
	newCount := atomic.AddInt32(&s.activeCount, -1)
	log.Println("Connection removed. Active:", newCount)
}

// Shutdown gracefully closes all active connections and waits for sessions to finish.
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

// serveListener handles accepting connections and spawning sessions for a given listener.
func (s *Server) serveListener(ln net.Listener, isTLS bool) {
	defer ln.Close()
	addr := ln.Addr().String()
	if isTLS {
		log.Printf("Listening (TLS) on %s", addr)
	} else {
		log.Printf("Listening on %s", addr)
	}
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
			sess := &Session{client: conn, server: s, log: "Connection: " + conn.RemoteAddr().String()}
			go sess.Process()
		}
	}
}

// ListenAndServe starts the TCP server and accepts incoming client connections.
//
// For each new connection, a Session is created and run in a separate goroutine.
// The server periodically checks for shutdown signals and handles timeouts and errors gracefully.
func (s *Server) ListenAndServe() {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	s.serveListener(ln, false)
}

// ListenAndServeTLS starts the TLS server (typically on port 443) and accepts secure client connections.
//
// It ensures a valid certificate and key are present (generating them if needed), then listens for
// incoming TLS connections. Each connection is handled by a Session in a separate goroutine.
func (s *Server) ListenAndServeTLS() {
	err := certgen.GenerateCert(s.tlsCertFile, s.tlsKeyFile)
	if err != nil {
		log.Fatalf("Failed to generate self-signed cert: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate or key: %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	addr := fmt.Sprintf("%s:%d", s.host, 443)
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on TCP for TLS: %v", err)
	}
	ln := tls.NewListener(tcpLn, tlsConfig)
	s.serveListener(ln, true)
}

// NewServer constructs and returns a new Server with default configuration values.
//
// The returned server is ready to accept connections on the default address and port.
func NewServer() *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		host:        DefaultListenAddress,
		port:        DefaultListenPort,
		ctx:         ctx,
		cancel:      cancel,
		conns:       sync.Map{},
		tlsCertFile: "cert.pem",
		tlsKeyFile:  "key.pem",
	}
}

// StartServer launches the tunnel proxy server and manages its lifecycle.
//
// This function sets up signal handling for graceful shutdown and runs both the TCP and TLS
// servers in separate goroutines. It blocks until a shutdown signal is received, then stops
// the server and logs the shutdown event.
func StartServer() {
	s := NewServer()

	// Create a channel to receive OS signals for graceful shutdown.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Start the TCP server in a separate goroutine.
	go s.ListenAndServe()
	// Start the TLS server in a separate goroutine.
	go s.ListenAndServeTLS()

	// Block until a shutdown signal is received (e.g., Ctrl+C or SIGTERM).
	<-c
	// Signal received: stop the server and log shutdown.
	s.cancel()
	s.Shutdown()
	log.Println("Shutting down...")
}
