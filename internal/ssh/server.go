// Package ssh implements the SSH server configuration and connection handling logic.
package ssh

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

// NewConfig initializes the SSH server configuration.
// Loads or generates the host key, sets up password authentication, and returns the config.
func NewConfig() (*ssh.ServerConfig, error) {
	// Initialize the authentication system if not already done
	if GetUserDB() == nil {
		if err := InitializeAuth(""); err != nil {
			return nil, fmt.Errorf("failed to initialize authentication: %v", err)
		}
	}

	keyPath := "host_key"
	// Try to read existing host key from disk.
	privateBytes, err := os.ReadFile(keyPath)
	if err != nil {
		// If not found, generate a new RSA key and save it.
		privateKey, err := NewRSAPrivateKey(4096)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %v", err)
		}
		privateBytes = RSAPrivateKeyPEM(privateKey)
		if err := os.WriteFile(keyPath, privateBytes, 0600); err != nil {
			return nil, fmt.Errorf("failed to save generated host key: %v", err)
		}
	}
	// Parse the PEM-encoded private key for SSH server use.
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host key: %v", err)
	}
	// Set up server config with password authentication.
	config := &ssh.ServerConfig{
		PasswordCallback: PasswordAuth,
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return "Welcome to ssh-ify.\n"
		},
	}

	// Set custom SSH version banner
	config.ServerVersion = "SSH-2.0-ssh-ify_1.0"

	config.AddHostKey(private)
	return config, nil
}

// ServeConn handles an incoming SSH connection.
// Accepts the connection, processes channels, and ensures proper cleanup.
// onAuthSuccess is an optional callback that gets called after successful SSH authentication.
func ServeConn(conn net.Conn, config *ssh.ServerConfig, onAuthSuccess func()) {
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
	ServePortForward(chans)
	// Close SSH connection after handling channels.
	sshConn.Close()
}
