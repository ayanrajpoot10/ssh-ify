// Package tunnel implements the proxy server and connection handling logic for ssh-ify.
//
// Features:
//   - Manages incoming TCP and TLS connections for HTTP, WebSocket, and SSH tunneling
//   - Handles protocol upgrades, including WebSocket and HTTP CONNECT
//   - Provides in-process SSH server integration for secure tunnels
//   - Tracks and manages active client connections with concurrency safety
//   - Supports graceful shutdown and connection cleanup
//   - Includes utility functions and constants for buffer sizes, timeouts, and HTTP responses
//   - Optimized I/O operations with reusable buffer pools for better performance
//
// Usage:
//  1. Create a new Server with NewServer
//  2. Start the server using ListenAndServe (for TCP) and ListenAndServeTLS (for TLS)
//  3. Each incoming connection is handled by a Session, which manages protocol upgrades and relays data
//  4. Utility functions and constants are available in utils.go for request parsing and configuration
//  5. High-performance I/O operations use reusable buffers from buffers.go to reduce allocations
//
// This package is intended for use by the ssh-ify proxy server and related internal components.
package tunnel
