// Package tunnel is the main entry point for the proxy server logic, handling startup and graceful shutdown.
package tunnel

import (
	"os"
	"os/signal"
	"syscall"
)

// RunProxy starts the proxy server and manages its lifecycle.
// Sets up signal handling for graceful shutdown and runs the server in a goroutine.
func RunProxy() {
	// Initialize the proxy server with listening address and port.
	s := &Server{
		host:    listeningAddr,
		port:    listeningPort,
		running: true,
		conns:   make(map[*ConnectionHandler]struct{}),
	}

	// Create a channel to receive OS signals for graceful shutdown.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Start the server in a separate goroutine so main can wait for shutdown signal.
	go s.serve()

	// Block until a shutdown signal is received (e.g., Ctrl+C or SIGTERM).
	<-c
	// Signal received: stop the server and log shutdown.
	s.running = false
	s.printLog("Shutting down...")
}
