package tunnel

import (
	"bufio"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"ssh-ify/internal/ssh"
)

// Session manages a single client connection for the ssh-ify tunnel proxy server.
//
// It encapsulates the state and logic for handling a client session, including
// protocol upgrades (WebSocket/SSH), bidirectional data relay, and connection cleanup.
// Each Session is associated with a parent Server and maintains references to both
// the client and target connections.
type Session struct {
	client    net.Conn
	target    net.Conn
	server    *Server
	log       string
	sshConfig *ssh.ServerConfig
}

// Close safely closes both the client and target connections managed by this Session.
//
// This method is idempotent and ensures that resources are released only once.
func (s *Session) Close() {
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
	if s.target != nil {
		s.target.Close()
		s.target = nil
	}
}

// Process handles the lifecycle of a client connection from initial request to tunnel establishment.
//
// It parses the HTTP request, detects protocol upgrades (WebSocket/SSH), initializes the SSH server
// configuration if needed, and establishes the tunnel. All major events and errors are logged for auditing.
func (s *Session) Process() {
	log.Println(s.log + " - New Connection opened")

	// Set a read deadline to avoid hanging connections.
	s.client.SetReadDeadline(time.Now().Add(ClientReadTimeout))
	reader := bufio.NewReaderSize(s.client, BufferSize)
	var builder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// If client disconnects or read fails, log and close.
			log.Println(s.log + " - error reading from client: " + err.Error())
			log.Println(s.log + " - Closing connection due to read error.")
			return
		}
		builder.WriteString(line)
		// End of HTTP headers detected.
		if strings.HasSuffix(builder.String(), "\r\n\r\n") {
			break
		}
		// Prevent header overflow attacks.
		if builder.Len() > BufferSize {
			log.Println(s.log + " - error: header too large")
			s.client.Write([]byte("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"))
			return
		}
	}
	buf := builder.String()

	reqLines := strings.Split(buf, "\r\n")
	if len(reqLines) > 0 {
		log.Println(s.log + " - Request: " + reqLines[0])
		hostHeader := HeaderValue(reqLines[1:], "Host")
		if hostHeader != "" {
			log.Println(s.log + " - Host header: " + hostHeader)
		}
		cfIP := HeaderValue(reqLines[1:], "CF-Connecting-IP")
		if cfIP != "" {
			log.Println(s.log + " - CF-Connecting-IP header: " + cfIP)
		}
	}

	// Remove read deadline for rest of session.
	s.client.SetReadDeadline(time.Time{})

	// Check for Upgrade header using HeaderValue utility.
	upgradeHeader := HeaderValue(reqLines[1:], "Upgrade")
	if upgradeHeader == "" {
		log.Println(s.log + " - No Upgrade header found. Closing connection.")
		s.Close()
		return
	}

	log.Println(s.log + " - WebSocket upgrade: using in-process SSH server.")
	// net.Pipe creates a pair of connected endpoints for tunneling.
	proxyEnd, sshEnd := net.Pipe()
	// Lazily initialize SSH config if needed.
	if s.sshConfig == nil {
		var err error
		s.sshConfig, err = ssh.NewConfig()
		if err != nil {
			log.Println(s.log + " - Error initializing SSH config: " + err.Error())
			return
		}
	}
	// Start SSH session in a goroutine for the tunnel endpoint.
	go ssh.ServeConn(sshEnd, s.sshConfig, func() {
		// Add connection to manager only after successful SSH authentication
		s.server.Add(s)
	})
	s.target = proxyEnd
	// Respond to client with protocol upgrade.
	s.client.Write([]byte(WebSocketUpgradeResponse))
	log.Println(s.log + " - Tunnel established.")
	s.Relay()
}

// Relay copies data bidirectionally between the client and target connections using goroutines.
//
// This method ensures proper cleanup after data transfer is complete, including closing connections
// and removing the Session from the server's active connection map. It is safe to call multiple times.
func (s *Session) Relay() {
	defer func() {
		s.Close()          // Clean up both connections
		s.server.Remove(s) // Remove from active map
		log.Println(s.log + " - Connection closed after data relay.")
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client → target
	go func() {
		defer wg.Done()
		_, err := io.Copy(s.target, s.client)
		if err != nil {
			log.Println(s.log+" - Error copying client to target:", err)
		}
		// Important: Closing target to unblock other io.Copy
		s.target.Close()
	}()

	// Copy target → client
	go func() {
		defer wg.Done()
		_, err := io.Copy(s.client, s.target)
		if err != nil {
			log.Println(s.log+" - Error copying target to client:", err)
		}
		// Important: Closing client to unblock other io.Copy
		s.client.Close()
	}()

	wg.Wait()
}
