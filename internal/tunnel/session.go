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
// Session encapsulates the state and logic for handling a client session, including
// protocol upgrades (WebSocket/SSH), bidirectional data relay, and connection cleanup.
// Each Session is associated with a parent Server and maintains references to both
// the client and target connections.
//
// Fields:
//   - client:    The client network connection
//   - target:    The target network connection (after upgrade)
//   - server:    The parent Server
//   - sshConfig: SSH server configuration for this session
//   - sessionID: Unique identifier for the session
type Session struct {
	client    net.Conn
	target    net.Conn
	server    *Server
	sshConfig *ssh.ServerConfig
	sessionID string
}

// Close safely closes both the client and target connections managed by this Session.
//
// This method is idempotent and ensures that resources are released only once.
//
// Example:
//
//	session.Close()
func (s *Session) Close() {
	if s.client != nil {
		s.client.Close()
	}
	if s.target != nil {
		s.target.Close()
	}
}

// Handle manages the lifecycle of a client connection from initial request to tunnel establishment.
//
// It parses the HTTP request, detects protocol upgrades (WebSocket/SSH), initializes the SSH server
// configuration if needed, and establishes the tunnel. All major events and errors are logged for auditing.
//
// Example:
//
//	sess.Handle()
func (s *Session) Handle() {
	log.Printf("[session %s] New connection opened", s.sessionID)

	// Set a read deadline to avoid hanging connections.
	s.client.SetReadDeadline(time.Now().Add(ClientReadTimeout))
	reader := bufio.NewReaderSize(s.client, BufferSize)
	var builder strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[session %s] Error reading from client: %v", s.sessionID, err)
			log.Printf("[session %s] Closing connection due to read error.", s.sessionID)
			return
		}
		builder.WriteString(line)
		if strings.HasSuffix(builder.String(), "\r\n\r\n") {
			break
		}
		// Prevent header overflow attacks.
		if builder.Len() > BufferSize {
			log.Printf("[session %s] Header too large, closing connection", s.sessionID)
			s.client.Write([]byte("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"))
			return
		}
	}
	buf := builder.String()

	reqLines := strings.Split(buf, "\r\n")
	if len(reqLines) > 0 {
		log.Printf("[session %s] Request received: %s", s.sessionID, reqLines[0])
		hostHeader := HeaderValue(reqLines[1:], "Host")
		if hostHeader != "" {
			log.Printf("[session %s] Host header: %s", s.sessionID, hostHeader)
		}
		cfIP := HeaderValue(reqLines[1:], "CF-Connecting-IP")
		if cfIP != "" {
			log.Printf("[session %s] CF-Connecting-IP header: %s", s.sessionID, cfIP)
		}
	}

	// Remove read deadline for rest of session.
	s.client.SetReadDeadline(time.Time{})

	// Handle WebSocket upgrade and tunnel setup using the new handler.
	if WebSocketHandler(s, reqLines[1:]) {
		s.Relay()
	}
}

// Relay copies data bidirectionally between the client and target connections using goroutines.
//
// This method ensures proper cleanup after data transfer is complete, including closing connections
// and removing the Session from the server's active connection map. It is safe to call multiple times.
//
// Example:
//
//	sess.Relay()
func (s *Session) Relay() {
	defer func() {
		s.Close()          // Clean up both connections
		s.server.Remove(s) // Remove from active map
		log.Printf("[session %s] Connection closed.", s.sessionID)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy client → target
	go func() {
		defer wg.Done()
		_, err := CopyWithBuffer(s.target, s.client)
		if err != nil && !isIgnorableError(err) {
			log.Printf("[session %s] Error copying client to target: %v", s.sessionID, err)
		}
		// Important: Closing target to unblock other io.Copy
		s.target.Close()
	}()

	// Copy target → client
	go func() {
		defer wg.Done()
		_, err := CopyWithBuffer(s.client, s.target)
		if err != nil && !isIgnorableError(err) {
			log.Printf("[session %s] Error copying target to client: %v", s.sessionID, err)
		}
		// Important: Closing client to unblock other io.Copy
		s.client.Close()
	}()

	wg.Wait()
}

// isIgnorableError returns true if the error is EOF or a known benign network error.
//
// Used internally to suppress logging for expected connection closure errors.
func isIgnorableError(err error) bool {
	if err == io.EOF {
		return true
	}
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection")
}
