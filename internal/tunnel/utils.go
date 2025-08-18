package tunnel

import (
	"strings"
	"time"
)

// BufferSize defines the buffer size (in bytes) for reading client requests.
const BufferSize = 4096 * 4

// ClientReadTimeout specifies the maximum duration to wait for client data before timing out.
const ClientReadTimeout = 60 * time.Second

// Note: For I/O operations, buffered copying with reusable buffers is implemented in buffers.go
// This provides better performance and reduced memory allocations compared to standard io.Copy.

// WebSocketUpgradeResponse is the HTTP response sent to clients to acknowledge a successful
// WebSocket protocol upgrade. This is used to establish SSH-over-WebSocket tunnels.
const WebSocketUpgradeResponse = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
	"Sec-WebSocket-Version: 13\r\n\r\n"

// DefaultListenAddress is the default address the proxy server listens on (all interfaces).
var DefaultListenAddress string = "0.0.0.0"

// DefaultListenPort is the default port the proxy server listens on (HTTP/WS).
var DefaultListenPort int = 80

// DefaultListenTLSPort is the default TLS listen port (HTTPS).
var DefaultListenTLSPort int = 443

// HeaderValue extracts the value of a specific HTTP header from a slice of header lines.
//
// It performs a case-insensitive search for the header name and returns the value if found, or an empty string otherwise.
// This utility is used for parsing incoming client requests and extracting metadata such as Host or custom headers.
//
// Parameters:
//   - headers: Slice of header lines (e.g., from strings.Split(request, "\r\n")).
//   - headerName: The name of the header to extract (case-insensitive).
//
// Returns:
//   - string: The value of the header, or "" if not found.
//
// Example:
//
//	host := tunnel.HeaderValue(headers, "Host")
func HeaderValue(headers []string, headerName string) string {
	headerNameLower := strings.ToLower(headerName)
	for _, line := range headers {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(parts[0])) == headerNameLower {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}
