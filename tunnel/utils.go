// Package tunnel provides utility functions and constants for the proxy server.
package tunnel

import (
	"strings"
	"time"
)

// BUFLEN defines the buffer size for reading client requests.
// TIMEOUT specifies the read deadline for client connections.
// RESPONSE is the HTTP response sent for protocol upgrades.
const (
	BUFLEN   = 4096 * 4
	TIMEOUT  = 60 * time.Second
	RESPONSE = "HTTP/1.1 101 Switching Protocols\r\nContent-Length: 104857600000\r\n\r\n"
)

// listeningAddr is the address the proxy server listens on.
// listeningPort is the port the proxy server listens on.
var (
	listeningAddr string = "0.0.0.0"
	listeningPort int    = 80
)

// findHeader extracts the value of a header from the HTTP request string.
// Returns the header value or an empty string if not found.
func findHeader(head, header string) string {
	// Simple header extraction: find "Header: " and return value up to CRLF.
	idx := strings.Index(head, header+": ")
	if idx == -1 {
		return ""
	}
	start := idx + len(header) + 2
	end := strings.Index(head[start:], "\r\n")
	if end == -1 {
		return ""
	}
	return head[start : start+end]
}
