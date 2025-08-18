package tunnel

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"ssh-ify/pkg/certgen"
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
