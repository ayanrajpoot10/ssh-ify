// Package tunnel implements the proxy server, managing incoming connections and concurrency.
package tunnel

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Server manages incoming connections and proxy logic for the tunnel proxy server.
// It tracks active connections, handles logging, and ensures thread-safe operations.
type Server struct {
	host        string
	port        int
	running     bool
	conns       map[*Handler]struct{}
	mu          sync.Mutex
	tlsCertFile string // Path to TLS certificate file
	tlsKeyFile  string // Path to TLS key file
	tlsEnabled  bool   // Whether to enable TLS
}

// AddConnection adds a new connection to the server's active connection map if running.
func (s *Server) Add(conn *Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		s.conns[conn] = struct{}{}
		log.Println("Connection added. Active:", len(s.conns))
	}
}

// RemoveConnection removes a connection from the server's active connection map.
func (s *Server) Remove(conn *Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
	log.Println("Connection removed. Active:", len(s.conns))
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
		s.Add(h)
		// Handle connection concurrently.
		go h.Process()
	}
	// Listener closed after shutdown.
	ln.Close()
}

// ListenAndServeTLS listens for incoming TLS connections on port 443 and spawns handlers for each connection.
// Requires valid certificate and key files.
func (s *Server) ListenAndServeTLS() {
	if !s.tlsEnabled {
		log.Println("TLS is not enabled. Skipping ListenAndServeTLS.")
		return
	}
	// Generate self-signed cert if needed
	err := generateSelfSignedCert(s.tlsCertFile, s.tlsKeyFile)
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
		s.Add(h)
		go h.Process()
	}
	ln.Close()
}
