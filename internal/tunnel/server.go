package tunnel

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
)

// Server manages all incoming TCP and TLS connections for the ssh-ify tunnel proxy server.
//
// Server tracks active client connections and ensures thread-safe operations using sync primitives.
// It supports both plain TCP and TLS (HTTPS/WebSocket) connections and provides methods for graceful startup and shutdown.
//
// Fields:
//   - host:        Listen address
//   - port:        Listen port
//   - ctx:         Context for cancellation
//   - cancel:      Cancel function for context
//   - conns:       Map of active sessions (concurrency safe)
//   - activeCount: Atomic counter for active connections
//   - tlsCertFile: Path to TLS certificate file
//   - tlsKeyFile:  Path to TLS key file
//   - wg:          WaitGroup to track active sessions
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
//
// Example:
//
//	tunnel.StartServer()
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
