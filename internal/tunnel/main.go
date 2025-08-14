// Package tunnel is the main entry point for the proxy server logic, handling startup and graceful shutdown.
package tunnel

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// StartServer starts the proxy server and manages its lifecycle.
// Sets up signal handling for graceful shutdown and runs the server in a goroutine.
func StartServer() {
	// Initialize the proxy server with listening address and port, and TLS config.
	s := &Server{
		host:        DefaultListenAddress,
		port:        DefaultListenPort,
		running:     true,
		conns:       sync.Map{},
		tlsCertFile: "cert.pem",
		tlsKeyFile:  "key.pem",
	}

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
	s.running = false
	log.Println("Shutting down...")
}
