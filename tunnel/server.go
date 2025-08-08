// Package tunnel implements the proxy server, managing incoming connections and concurrency.
package tunnel

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Server manages incoming connections and proxy logic for the tunnel proxy server.
// It tracks active connections, handles logging, and ensures thread-safe operations.
type Server struct {
	host    string
	port    int
	running bool
	conns   map[*ConnectionHandler]struct{}
	mu      sync.Mutex
}

// AddConnection adds a new connection to the server's active connection map if running.
func (s *Server) AddConnection(conn *ConnectionHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		s.conns[conn] = struct{}{}
		log.Println("Connection added. Active:", len(s.conns))
	}
}

// RemoveConnection removes a connection from the server's active connection map.
func (s *Server) RemoveConnection(conn *ConnectionHandler) {
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
	log.Println(fmt.Sprintf("Listening on %s", addr))
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
		h := &ConnectionHandler{client: conn, server: s, log: "Connection: " + conn.RemoteAddr().String()}
		s.AddConnection(h)
		// Handle connection concurrently.
		go h.ProcessConnection()
	}
	// Listener closed after shutdown.
	ln.Close()
}
