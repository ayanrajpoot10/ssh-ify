// Package tunnel provides connection handling logic for the proxy server, including HTTP and WebSocket upgrades.
package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	sshserver "ssh-ify/internal/ssh"

	"golang.org/x/crypto/ssh"
)

// Handler manages a single client connection, including target connection, logging, and SSH upgrades.
type Handler struct {
	client       net.Conn
	target       net.Conn
	server       *Server
	clientClosed bool
	targetClosed bool
	log          string
	startTime    time.Time
	sshConfig    *ssh.ServerConfig
}

// Close safely closes both client and target connections, marking them as closed.
func (h *Handler) Close() {
	if !h.clientClosed && h.client != nil {
		h.client.Close()
		h.clientClosed = true
	}
	if !h.targetClosed && h.target != nil {
		h.target.Close()
		h.targetClosed = true
	}
}

// Process processes the client connection, parses the HTTP request, detects upgrades, and manages tunnel establishment.
// Handles WebSocket upgrades, HTTP CONNECT, and logs all major events and errors.
func (h *Handler) Process() {
	h.startTime = time.Now()
	log.Println(h.log + " - Connection opened at " + h.startTime.Format(time.RFC3339))

	// Set a read deadline to avoid hanging connections.
	h.client.SetReadDeadline(time.Now().Add(ClientReadTimeout))
	reader := bufio.NewReaderSize(h.client, BufferSize)
	var builder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// If client disconnects or read fails, log and close.
			log.Println(h.log + " - error reading from client: " + err.Error())
			log.Println(h.log + " - Closing connection due to read error.")
			return
		}
		builder.WriteString(line)
		// End of HTTP headers detected.
		if strings.HasSuffix(builder.String(), "\r\n\r\n") {
			break
		}
		// Prevent header overflow attacks.
		if builder.Len() > BufferSize {
			log.Println(h.log + " - error: header too large")
			h.client.Write([]byte("HTTP/1.1 400 HeaderTooLarge\r\n\r\n"))
			return
		}
	}
	buf := builder.String()

	reqLines := strings.Split(buf, "\r\n")
	if len(reqLines) > 0 {
		log.Println(h.log + " - Request: " + reqLines[0])
		// Print Host header if present
		for _, line := range reqLines[1:] {
			lowerLine := strings.ToLower(line)
			if strings.HasPrefix(lowerLine, "host:") {
				hostHeader := strings.TrimSpace(line[5:])
				log.Println(h.log + " - Host header: " + hostHeader)
			}
			if strings.HasPrefix(lowerLine, "cf-connecting-ip:") {
				cfIP := strings.TrimSpace(line[len("CF-Connecting-IP:"):])
				log.Println(h.log + " - CF-Connecting-IP header: " + cfIP)
			}
		}
	}

	// Remove read deadline for rest of session.
	h.client.SetReadDeadline(time.Time{})

	// Detect WebSocket upgrade (used for SSH tunneling).
	upgrade := HeaderValue(buf, "Upgrade")
	if upgrade == "websocket" {
		log.Println(h.log + " - WebSocket upgrade: using in-process SSH server.")
		// net.Pipe creates a pair of connected endpoints for tunneling.
		proxyEnd, sshEnd := net.Pipe()
		// Lazily initialize SSH config if needed.
		if h.sshConfig == nil {
			var err error
			h.sshConfig, err = sshserver.NewConfig()
			if err != nil {
				log.Println(h.log + " - Error initializing SSH config: " + err.Error())
				return
			}
		}
		// Start SSH handler in a goroutine for the tunnel endpoint.
		go sshserver.ServeConn(sshEnd, h.sshConfig)
		h.target = proxyEnd
		h.targetClosed = false
		// Respond to client with protocol upgrade.
		h.client.Write([]byte(WebSocketUpgradeResponse))
		log.Println(h.log + " - Tunnel established.")
		h.Relay()
		return
	} else if upgrade != "" {
		// Other upgrade header present (not websocket).
		log.Println(h.log + " - Upgrade header present: " + upgrade)
	}
}

// ConnectTarget establishes a TCP connection to the specified host and port.
// Returns an error if the connection fails.
func (h *Handler) ConnectTarget(host string) error {
	var port string
	// Parse host:port, default to DefaultListenPort if not specified.
	if i := strings.Index(host, ":"); i != -1 {
		port = host[i+1:]
		host = host[:i]
	} else {
		port = fmt.Sprintf("%d", DefaultListenPort)
	}
	addr := net.JoinHostPort(host, port)
	log.Println(h.log + " - Connecting to target: " + addr)
	// Use DialTimeout to avoid hanging on unreachable targets.
	target, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Println(h.log + " - Error connecting to target: " + err.Error())
		return err
	}
	log.Println(h.log + " - Connected to target: " + addr)
	h.target = target
	h.targetClosed = false
	return nil
}

// Relay relays data bidirectionally between the client and target connection using goroutines.
// Ensures proper cleanup after transfer is complete.
func (h *Handler) Relay() {
	defer func() {
		h.Close()          // Clean up both connections
		h.server.Remove(h) // Remove from active map
		log.Println(h.log + " - Connection closed after data relay.")
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client → target
	go func() {
		defer wg.Done()
		_, err := io.Copy(h.target, h.client)
		if err != nil {
			log.Println(h.log+" - Error copying client to target:", err)
		}
		// Important: Closing target to unblock other io.Copy
		h.target.Close()
	}()

	// Copy target → client
	go func() {
		defer wg.Done()
		_, err := io.Copy(h.client, h.target)
		if err != nil {
			log.Println(h.log+" - Error copying target to client:", err)
		}
		// Important: Closing client to unblock other io.Copy
		h.client.Close()
	}()

	wg.Wait()
}
