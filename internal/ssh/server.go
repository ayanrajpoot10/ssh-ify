package ssh

import (
	"net"

	"golang.org/x/crypto/ssh"
)

// HandleSSHConnection handles an incoming SSH connection for the ssh-ify server.
//
// It performs the SSH handshake, processes port forwarding channels, and ensures
// proper cleanup of resources. The optional onAuthSuccess callback is invoked after
// successful authentication, allowing for custom logic (such as connection tracking).
//
// Parameters:
//   - conn: The underlying network connection to upgrade to SSH.
//   - config: The SSH server configuration (typically from NewConfig).
//   - onAuthSuccess: Optional callback invoked after successful authentication (may be nil).
//
// Example:
//
//	ssh.HandleSSHConnection(conn, config, func() { log.Println("Authenticated!") })
func HandleSSHConnection(conn net.Conn, config *ssh.ServerConfig, onAuthSuccess func()) {
	// Accept the incoming SSH connection and extract channels/requests.
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		// If handshake fails, close connection.
		conn.Close()
		return
	}

	// Call the success callback if provided (authentication was successful)
	if onAuthSuccess != nil {
		onAuthSuccess()
	}

	// Discard global requests (not used).
	go ssh.DiscardRequests(reqs)
	// Handle port forwarding channels.
	HandleSSHChannels(chans)
	// Close SSH connection after handling channels.
	sshConn.Close()
}
