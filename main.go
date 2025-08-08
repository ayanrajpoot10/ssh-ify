// Package main is the entry point for the ssh-ify proxy application.
// It initializes and starts the tunnel proxy server.
package main

import (
	tunnel "ssh-ify/tunnel"
)

// main initializes and starts the tunnel proxy server.
// It delegates the proxy logic to the tunnel package.
func main() {
	// Start the proxy server defined in the tunnel package.
	tunnel.StartProxyServer()
}
