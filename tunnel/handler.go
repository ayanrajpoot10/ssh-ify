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

	sshserver "ssh-ify/ssh"

	"golang.org/x/crypto/ssh"
)

// ConnectionHandler manages a single client connection, including target connection, logging, and SSH upgrades.
type ConnectionHandler struct {
	client       net.Conn
	target       net.Conn
	server       *Server
	clientClosed bool
	targetClosed bool
	log          string
	startTime    time.Time
	sshConfig    *ssh.ServerConfig
}

// close safely closes both client and target connections, marking them as closed.
func (c *ConnectionHandler) close() {
	if !c.clientClosed && c.client != nil {
		c.client.Close()
		c.clientClosed = true
	}
	if !c.targetClosed && c.target != nil {
		c.target.Close()
		c.targetClosed = true
	}
}

// handle processes the client connection, parses the HTTP request, detects upgrades, and manages tunnel establishment.
// Handles WebSocket upgrades, HTTP CONNECT, and logs all major events and errors.
func (c *ConnectionHandler) handle() {
	c.startTime = time.Now()
	log.Println(c.log + " - Connection opened at " + c.startTime.Format(time.RFC3339))

	// Set a read deadline to avoid hanging connections.
	log.Println(c.log + " - Setting client read deadline: " + TIMEOUT.String())
	c.client.SetReadDeadline(time.Now().Add(TIMEOUT))
	reader := bufio.NewReaderSize(c.client, BUFLEN)
	var bufBuilder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// If client disconnects or read fails, log and close.
			log.Println(c.log + " - error reading from client: " + err.Error())
			log.Println(c.log + " - Closing connection due to read error.")
			return
		}
		bufBuilder.WriteString(line)
		// End of HTTP headers detected.
		if strings.HasSuffix(bufBuilder.String(), "\r\n\r\n") {
			break
		}
		// Prevent header overflow attacks.
		if bufBuilder.Len() > BUFLEN {
			log.Println(c.log + " - error: header too large")
			c.client.Write([]byte("HTTP/1.1 400 HeaderTooLarge\r\n\r\n"))
			return
		}
	}
	buf := bufBuilder.String()

	reqLines := strings.Split(buf, "\r\n")
	if len(reqLines) > 0 {
		log.Println(c.log + " - Request: " + reqLines[0])
	}

	// Remove read deadline for rest of session.
	c.client.SetReadDeadline(time.Time{})

	// Detect WebSocket upgrade (used for SSH tunneling).
	upgrade := findHeader(buf, "Upgrade")
	if upgrade == "websocket" {
		log.Println(c.log + " - WebSocket upgrade: using in-process SSH server.")
		// net.Pipe creates a pair of connected endpoints for tunneling.
		proxyEnd, sshEnd := net.Pipe()
		// Lazily initialize SSH config if needed.
		if c.sshConfig == nil {
			var err error
			c.sshConfig, err = sshserver.InitSSHServerConfig()
			if err != nil {
				log.Println(c.log + " - Error initializing SSH config: " + err.Error())
				return
			}
		}
		// Start SSH handler in a goroutine for the tunnel endpoint.
		go sshserver.HandleSSHConn(sshEnd, c.sshConfig)
		c.target = proxyEnd
		c.targetClosed = false
		// Respond to client with protocol upgrade.
		c.client.Write([]byte(RESPONSE))
		log.Println(c.log + " - Tunnel established.")
		c.doCONNECT()
		return
	} else if strings.HasPrefix(reqLines[0], "CONNECT ") {
		log.Println(c.log + " - HTTP CONNECT: " + reqLines[0])
		parts := strings.Split(reqLines[0], " ")
		if len(parts) < 2 {
			// Malformed CONNECT request line.
			log.Println(c.log + " - Malformed CONNECT request line.")
			c.client.Write([]byte("HTTP/1.1 400 BadRequest\r\n\r\n"))
			return
		}
		targetAddr := parts[1]
		// Attempt to connect to requested target.
		if err := c.connectTarget(targetAddr); err != nil {
			log.Println(c.log + " - Error connecting to target: " + err.Error())
			c.client.Write([]byte("HTTP/1.1 502 BadGateway\r\n\r\n"))
			return
		}
		// Connection established, inform client.
		c.client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		log.Println(c.log + " - Tunnel established.")
		c.doCONNECT()
		return
	} else if upgrade != "" {
		// Other upgrade header present (not websocket).
		log.Println(c.log + " - Upgrade header present: " + upgrade)
	}
}

// connectTarget establishes a TCP connection to the specified host and port.
// Returns an error if the connection fails.
func (c *ConnectionHandler) connectTarget(host string) error {
	var port string
	// Parse host:port, default to listeningPort if not specified.
	if i := strings.Index(host, ":"); i != -1 {
		port = host[i+1:]
		host = host[:i]
	} else {
		port = fmt.Sprintf("%d", listeningPort)
	}
	addr := net.JoinHostPort(host, port)
	log.Println(c.log + " - Connecting to target: " + addr)
	// Use DialTimeout to avoid hanging on unreachable targets.
	target, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Println(c.log + " - Error connecting to target: " + err.Error())
		return err
	}
	log.Println(c.log + " - Connected to target: " + addr)
	c.target = target
	c.targetClosed = false
	return nil
}

// doCONNECT relays data bidirectionally between the client and target connection using goroutines.
// Ensures proper cleanup after transfer is complete.
func (c *ConnectionHandler) doCONNECT() {
	defer func() {
		c.close()                 // Clean up both connections
		c.server.removeConn(c)    // Remove from active map
		log.Println(c.log + " - Connection closed after data relay.")
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client → target
	go func() {
		defer wg.Done()
		_, err := io.Copy(c.target, c.client)
		if err != nil {
			log.Println(c.log + " - Error copying client to target:", err)
		}
		// Important: Closing target to unblock other io.Copy
		c.target.Close()
	}()

	// Copy target → client
	go func() {
		defer wg.Done()
		_, err := io.Copy(c.client, c.target)
		if err != nil {
			log.Println(c.log + " - Error copying target to client:", err)
		}
		// Important: Closing client to unblock other io.Copy
		c.client.Close()
	}()

	wg.Wait()
}
