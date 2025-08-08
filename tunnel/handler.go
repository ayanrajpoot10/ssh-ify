// Package tunnel provides connection handling logic for the proxy server, including HTTP and WebSocket upgrades.
package tunnel

import (
	"bufio"
	"fmt"
	"io"
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
	c.server.printLog(c.log + " - Connection opened at " + c.startTime.Format(time.RFC3339))
	// Ensure connection cleanup and logging on exit (even on error).
	defer func() {
		c.close()
		c.server.removeConn(c)
		elapsed := time.Since(c.startTime)
		c.server.printLog(c.log + " - Connection closed. Duration: " + elapsed.String())
	}()

	// Set a read deadline to avoid hanging connections.
	c.server.printLog(c.log + " - Setting client read deadline: " + TIMEOUT.String())
	c.client.SetReadDeadline(time.Now().Add(TIMEOUT))
	reader := bufio.NewReaderSize(c.client, BUFLEN)
	var bufBuilder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// If client disconnects or read fails, log and close.
			c.server.printLog(c.log + " - error reading from client: " + err.Error())
			c.server.printLog(c.log + " - Closing connection due to read error.")
			return
		}
		bufBuilder.WriteString(line)
		// End of HTTP headers detected.
		if strings.HasSuffix(bufBuilder.String(), "\r\n\r\n") {
			break
		}
		// Prevent header overflow attacks.
		if bufBuilder.Len() > BUFLEN {
			c.server.printLog(c.log + " - error: header too large")
			c.client.Write([]byte("HTTP/1.1 400 HeaderTooLarge\r\n\r\n"))
			return
		}
	}
	buf := bufBuilder.String()

	reqLines := strings.Split(buf, "\r\n")
	if len(reqLines) > 0 {
		c.server.printLog(c.log + " - Request: " + reqLines[0])
	}

	// Remove read deadline for rest of session.
	c.client.SetReadDeadline(time.Time{})

	// Detect WebSocket upgrade (used for SSH tunneling).
	upgrade := findHeader(buf, "Upgrade")
	if upgrade == "websocket" {
		c.server.printLog(c.log + " - WebSocket upgrade: using in-process SSH server.")
		// net.Pipe creates a pair of connected endpoints for tunneling.
		proxyEnd, sshEnd := net.Pipe()
		// Lazily initialize SSH config if needed.
		if c.sshConfig == nil {
			var err error
			c.sshConfig, err = sshserver.InitSSHServerConfig()
			if err != nil {
				c.server.printLog(c.log + " - Error initializing SSH config: " + err.Error())
				return
			}
		}
		// Start SSH handler in a goroutine for the tunnel endpoint.
		go sshserver.HandleSSHConn(sshEnd, c.sshConfig)
		c.target = proxyEnd
		c.targetClosed = false
		// Respond to client with protocol upgrade.
		c.client.Write([]byte(RESPONSE))
		c.server.printLog(c.log + " - Tunnel established.")
		c.doCONNECT()
		return
	} else if strings.HasPrefix(reqLines[0], "CONNECT ") {
		c.server.printLog(c.log + " - HTTP CONNECT: " + reqLines[0])
		parts := strings.Split(reqLines[0], " ")
		if len(parts) < 2 {
			// Malformed CONNECT request line.
			c.server.printLog(c.log + " - Malformed CONNECT request line.")
			c.client.Write([]byte("HTTP/1.1 400 BadRequest\r\n\r\n"))
			return
		}
		targetAddr := parts[1]
		// Attempt to connect to requested target.
		if err := c.connectTarget(targetAddr); err != nil {
			c.server.printLog(c.log + " - Error connecting to target: " + err.Error())
			c.client.Write([]byte("HTTP/1.1 502 BadGateway\r\n\r\n"))
			return
		}
		// Connection established, inform client.
		c.client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		c.server.printLog(c.log + " - Tunnel established.")
		c.doCONNECT()
		return
	} else if upgrade != "" {
		// Other upgrade header present (not websocket).
		c.server.printLog(c.log + " - Upgrade header present: " + upgrade)
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
	c.server.printLog(c.log + " - Connecting to target: " + addr)
	// Use DialTimeout to avoid hanging on unreachable targets.
	target, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		c.server.printLog(c.log + " - Error connecting to target: " + err.Error())
		return err
	}
	c.server.printLog(c.log + " - Connected to target: " + addr)
	c.target = target
	c.targetClosed = false
	return nil
}

// doCONNECT relays data bidirectionally between the client and target connection using goroutines.
// Ensures proper cleanup after transfer is complete.
func (c *ConnectionHandler) doCONNECT() {
	var wg sync.WaitGroup
	wg.Add(2)
	// Relay data from client to target.
	go func() {
		_, err := io.Copy(c.target, c.client)
		if err != nil {
			c.server.printLog(c.log + " - Error copying client to target: " + err.Error())
		}
		wg.Done()
	}()
	// Relay data from target to client.
	go func() {
		_, err := io.Copy(c.client, c.target)
		if err != nil {
			c.server.printLog(c.log + " - Error copying target to client: " + err.Error())
		}
		wg.Done()
	}()
	// Wait for both directions to finish before closing connection.
	wg.Wait()
	c.close()
}
