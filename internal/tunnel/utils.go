package tunnel

import (
	"strings"
	"time"
)

// BufferSize defines the buffer size for reading client requests.
// ClientReadTimeout specifies the read deadline for client connections.
// WebSocketUpgradeResponse is the HTTP response sent for protocol upgrades.
const (
	BufferSize               = 4096 * 4
	ClientReadTimeout        = 60 * time.Second
	WebSocketUpgradeResponse = "HTTP/1.1 101 Switching Protocols\r\nContent-Length: 104857600000\r\n\r\n"
)

// listeningAddr is the address the proxy server listens on.
// listeningPort is the port the proxy server listens on.
var (
	DefaultListenAddress string = "0.0.0.0"
	DefaultListenPort    int    = 80
)

// HeaderValue extracts the value of a header from the HTTP request string.
// Returns the header value or an empty string if not found.
func HeaderValue(request, headerName string) string {
	idx := strings.Index(request, headerName+": ")
	if idx == -1 {
		return ""
	}
	start := idx + len(headerName) + 2
	end := strings.Index(request[start:], "\r\n")
	if end == -1 {
		return ""
	}
	return request[start : start+end]
}
