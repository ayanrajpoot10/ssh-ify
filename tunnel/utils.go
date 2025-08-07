package tunnel

import (
	"strings"
	"time"
)

const (
	BUFLEN   = 4096 * 4
	TIMEOUT  = 60 * time.Second
	RESPONSE = "HTTP/1.1 101 Switching Protocols\r\nContent-Length: 104857600000\r\n\r\n"
)

var (
	listeningAddr string = "0.0.0.0"
	listeningPort int    = 80
)

// findHeader extracts the value of a header from the HTTP request.
func findHeader(head, header string) string {
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
