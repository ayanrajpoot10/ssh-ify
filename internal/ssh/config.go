package ssh

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// ServerConfig is a type alias for ssh.ServerConfig.
//
// This alias allows other internal packages (such as tunnel/session.go) to use the SSH server configuration
// without directly importing golang.org/x/crypto/ssh, improving modularity and encapsulation of SSH server details.
type ServerConfig = ssh.ServerConfig

// NewConfig initializes and returns a new SSH server configuration for ssh-ify.
//
// This function loads or generates the SSH host key, sets up password authentication
// using the user database, and configures the SSH version banner. It ensures the
// authentication system is initialized before returning a usable config.
//
// Returns:
//   - *ssh.ServerConfig: The configured SSH server settings.
//   - error: If host key generation, loading, or parsing fails, or if authentication cannot be initialized.
//
// Example:
//
//	config, err := ssh.NewConfig()
//	if err != nil { ... }
//	// Use config to accept SSH connections
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
