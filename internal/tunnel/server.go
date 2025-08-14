// Package tunnel implements the proxy server, managing incoming connections and concurrency.
package tunnel

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ssh-ify/pkg/certgen"
)

// Server manages incoming connections and proxy logic for the tunnel proxy server.
// It tracks active connections, handles logging, and ensures thread-safe operations.
type Server struct {
	host        string
	port        int
	running     bool
	conns       sync.Map // map[*Handler]struct{} for concurrency safety
	activeCount int32    // atomic counter for active connections
	tlsCertFile string   // Path to TLS certificate file
	tlsKeyFile  string   // Path to TLS key file
}

// Add adds a new connection to the server's active connection map if running.
func (s *Server) Add(conn *Handler) {
	if s.running {
		s.conns.Store(conn, struct{}{})
		newCount := atomic.AddInt32(&s.activeCount, 1)
		log.Println("Connection added. Active:", newCount)
	}
}

// Remove removes a connection from the server's active connection map.
func (s *Server) Remove(conn *Handler) {
	s.conns.Delete(conn)
	newCount := atomic.AddInt32(&s.activeCount, -1)
	log.Println("Connection removed. Active:", newCount)
}

// ListenAndServe listens for incoming TCP connections and spawns handlers for each connection.
// Handles timeouts, errors, and ensures proper cleanup on shutdown.
func (s *Server) ListenAndServe() {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	s.running = true
	log.Printf("Listening on %s", addr)
	for s.running {
		// Set a short deadline to allow periodic shutdown checks.
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			// If timeout, check running flag again.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Any other error: exit loop and close listener.
			break
		}
		// Create a handler for each new connection.
		h := &Handler{client: conn, server: s, log: "Connection: " + conn.RemoteAddr().String()}
		go h.Process()
	}
	// Listener closed after shutdown.
	ln.Close()
}

// ListenAndServeTLS listens for incoming TLS connections on port 443 and spawns handlers for each connection.
// Requires valid certificate and key files.
func (s *Server) ListenAndServeTLS() {
	// Always run TLS server
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
	s.running = true
	log.Printf("Listening (TLS) on %s", addr)
	for s.running {
		// Set deadline for underlying TCP listener
		if inner, ok := tcpLn.(*net.TCPListener); ok {
			inner.SetDeadline(time.Now().Add(2 * time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		h := &Handler{client: conn, server: s, log: "TLS Connection: " + conn.RemoteAddr().String()}
		go h.Process()
	}
	ln.Close()
}
