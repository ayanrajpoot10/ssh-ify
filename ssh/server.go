package ssh

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

// InitSSHServerConfig initializes the SSH server configuration.
func InitSSHServerConfig() (*ssh.ServerConfig, error) {
	keyPath := "host_key"
	privateBytes, err := os.ReadFile(keyPath)
	if err != nil {
		privateKey, err := GeneratePrivateKey(4096)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate private key: %v", err)
		}
		privateBytes = EncodePrivateKeyToPEM(privateKey)
		if err := os.WriteFile(keyPath, privateBytes, 0600); err != nil {
			return nil, fmt.Errorf("Failed to save generated host key: %v", err)
		}
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse host key: %v", err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: PasswordAuthCallback,
	}
	config.AddHostKey(private)
	return config, nil
}

// HandleSSHConn handles an incoming SSH connection.
func HandleSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	HandleChannels(chans)
	sshConn.Close()
}
