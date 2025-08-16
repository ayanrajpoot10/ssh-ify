package tunnel

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"
)

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
			sess := &Session{client: conn, server: s}
			go sess.Process()
		}
	}
}

// ListenAndServe starts the tunnel server in plain TCP mode and begins accepting incoming client connections.
// It listens on the configured host and port, and spawns a new session for each connection.
func (s *Server) ListenAndServe() {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	serveListener(s, ln)
}

// ListenAndServeTLS starts the tunnel server in TLS mode and begins accepting secure client connections.
// It loads the configured TLS certificate and key, listens on the standard HTTPS port (443),
// and spawns a new session for each secure connection.
func (s *Server) ListenAndServeTLS() {
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
	serveListener(s, ln)
}
