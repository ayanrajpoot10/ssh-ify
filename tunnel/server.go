package tunnel

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Server manages incoming connections and proxy logic.
type Server struct {
	host    string
	port    int
	running bool
	conns   map[*ConnectionHandler]struct{}
	mu      sync.Mutex
	logMu   sync.Mutex
}

func (s *Server) printLog(msg string) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	log.Println(msg)
}

func (s *Server) addConn(conn *ConnectionHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		s.conns[conn] = struct{}{}
	}
}

func (s *Server) removeConn(conn *ConnectionHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

func (s *Server) serve() {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	s.running = true
	s.printLog(fmt.Sprintf("Listening on %s", addr))
	for s.running {
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		h := &ConnectionHandler{client: conn, server: s, log: "Connection: " + conn.RemoteAddr().String()}
		s.addConn(h)
		go h.handle()
	}
	ln.Close()
}
