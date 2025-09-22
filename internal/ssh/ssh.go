// Package ssh provides core SSH server functionality for ssh-ify.
//
// Features:
//   - User authentication (password-based, pluggable via usermgmt)
//   - Host key generation and management (RSA, PEM encoding)
//   - SSH server configuration and version banner customization
//   - Secure connection handling and session management
//   - Port forwarding (direct-tcpip) and channel data relay with optimized buffering
//
// Usage:
//  1. Initialize authentication with InitializeAuth (typically at startup)
//  2. Create a server config with NewConfig
//  3. Accept incoming connections and handle them with HandleSSHConnection
//  4. Use HandleSSHChannels to process port forwarding channels with buffer pooling
//
// This package is intended for use by the ssh-ify server and related internal components.
package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/ayanrajpoot10/ssh-ify/internal/usermgmt"

	"golang.org/x/crypto/ssh"
)

// Constants
const (
	// SSHBufferPoolSize is the size of each buffer in the SSH pool (32KB)
	// Optimized for SSH channel data transfer
	SSHBufferPoolSize = 32 * 1024
)

// Type aliases
// ServerConfig is a type alias for ssh.ServerConfig.
//
// This alias allows other internal packages (such as the tunnel package) to use the SSH server configuration
// without directly importing golang.org/x/crypto/ssh, improving modularity and encapsulation of SSH server details.
type ServerConfig = ssh.ServerConfig

// Global variables
var (
	// Global user database instance
	userDB *usermgmt.UserDB

	// sshBufferPool is a pool of reusable byte slices for SSH I/O operations
	sshBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, SSHBufferPoolSize)
			return &buf
		},
	}
)

// Buffer pool functions
// getSSHBuffer retrieves a buffer from the SSH pool
func getSSHBuffer() *[]byte {
	return sshBufferPool.Get().(*[]byte)
}

// putSSHBuffer returns a buffer to the SSH pool for reuse
func putSSHBuffer(buf *[]byte) {
	sshBufferPool.Put(buf)
}

// CopyWithSSHBuffer performs buffered copying between src and dst using a pooled buffer
// optimized for SSH channel operations. This reduces memory allocations and GC pressure
// during high-frequency port forwarding operations.
//
// Parameters:
//   - dst: The destination writer
//   - src: The source reader
//
// Returns:
//   - int64: The number of bytes copied
//   - error: Any error that occurred during copying
func CopyWithSSHBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := getSSHBuffer()
	defer putSSHBuffer(buf)
	return io.CopyBuffer(dst, src, *buf)
}

// Authentication functions
// InitializeAuth sets up the global authentication system for SSH password validation.
//
// It creates a new user database instance (optionally at dbPath) and must be called
// before any authentication or user management functions are used. This enables
// password-based authentication for the SSH server.
//
// Parameters:
//   - dbPath: Path to the user database file. If empty, uses the default location.
//
// Returns:
//   - error: If initialization fails (should not occur in current implementation).
//
// Example:
//
//	err := ssh.InitializeAuth("")
func InitializeAuth(dbPath string) error {
	userDB = usermgmt.NewUserDB(dbPath)
	return nil
}

// GetUserDB returns the global user database instance used for authentication.
//
// Returns nil if InitializeAuth has not been called. This function is used by
// authentication callbacks and other internal components to access user data.
func GetUserDB() *usermgmt.UserDB {
	return userDB
}

// PasswordAuth implements ssh.PasswordCallback for custom SSH authentication.
//
// It validates the provided username and password against the user database and returns
// SSH permissions or an error. Used by the SSH server to authenticate incoming connections.
//
// Parameters:
//   - c: SSH connection metadata (contains username).
//   - password: The password provided by the client.
//
// Returns:
//   - *ssh.Permissions: Always nil (no custom permissions used).
//   - error: If authentication fails or the user database is not initialized.
//
// Example:
//
//	config.PasswordCallback = ssh.PasswordAuth
func PasswordAuth(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if userDB == nil {
		log.Printf("PasswordAuth: user database not initialized")
		return nil, fmt.Errorf("user database not initialized")
	}

	success := userDB.Authenticate(c.User(), string(password))
	if success {
		log.Printf("PasswordAuth: successful login for user '%s'", c.User())
		return nil, nil
	} else {
		log.Printf("PasswordAuth: failed login attempt for user '%s'", c.User())
		return nil, fmt.Errorf("invalid credentials")
	}
}

// Key generation functions
// NewRSAPrivateKey generates a new RSA private key of the specified bit size.
//
// This function is used for generating SSH host keys or other cryptographic operations
// requiring RSA keys. It validates the generated key for correctness before returning.
//
// Parameters:
//   - bitSize: The number of bits for the RSA key (e.g., 2048, 4096).
//
// Returns:
//   - *rsa.PrivateKey: The generated RSA private key.
//   - error: If key generation or validation fails.
//
// Example:
//
//	priv, err := ssh.NewRSAPrivateKey(4096)
//	if err != nil { ... }
func NewRSAPrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Generate RSA private key of given bit size.
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}
	// Validate generated key for correctness.
	if err := privateKey.Validate(); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// RSAPrivateKeyPEM encodes an RSA private key to PEM format for storage or transmission.
//
// This function marshals the RSA key to PKCS#1 DER format and wraps it in a PEM block.
// The result is suitable for use in SSH server configuration or for saving to disk.
//
// Parameters:
//   - privateKey: The RSA private key to encode.
//
// Returns:
//   - []byte: PEM-encoded private key data.
//
// Example:
//
//	pemBytes := ssh.RSAPrivateKeyPEM(priv)
func RSAPrivateKeyPEM(privateKey *rsa.PrivateKey) []byte {
	// Marshal RSA key to PKCS#1 DER format.
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	// Create PEM block for private key.
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	// Encode PEM block to memory and return.
	return pem.EncodeToMemory(privBlock)
}

// Configuration functions
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

// Channel handling functions
// ForwardData relays data bidirectionally between an SSH channel and a target TCP connection.
//
// This function launches goroutines for each direction (SSH→target and target→SSH),
// ensuring efficient, concurrent data transfer with reusable buffers. It waits for both
// directions to complete and then closes both connections to free resources.
//
// Parameters:
//   - ch: The SSH channel to relay data from/to.
//   - targetConn: The TCP connection to the target host.
//   - addr: The address of the target host (for logging).
//
// Example:
//
//	ForwardData(sshChannel, tcpConn, "example.com:80")
func ForwardData(ch ssh.Channel, targetConn net.Conn, addr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := CopyWithSSHBuffer(targetConn, ch)
		if err != nil && err != io.EOF {
			log.Printf("forwardChannel: Error copying SSH->%s: %v", addr, err)
		}
	}()
	go func() {
		defer wg.Done()
		_, err := CopyWithSSHBuffer(ch, targetConn)
		if err != nil && err != io.EOF {
			log.Printf("forwardChannel: Error copying %s->SSH: %v", addr, err)
		}
	}()
	wg.Wait()
	// Close connections after both directions are done
	targetConn.Close()
	ch.Close()
}

// HandleSSHChannels processes incoming SSH channels for port forwarding (direct-tcpip).
//
// It accepts only "direct-tcpip" channel types, parses the target address and port,
// and establishes a TCP connection to the requested destination. Each accepted channel
// is handled in a separate goroutine for concurrency. Unsupported or malformed channels
// are rejected with appropriate error messages.
//
// Parameters:
//   - chans: Channel of incoming SSH NewChannel requests.
//
// Example:
//
//	HandleSSHChannels(newChannelChan)
func HandleSSHChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		// Step 1: Validate channel type
		if !isDirectTCPIPChannel(newChannel) {
			log.Printf("HandleChannels: Unknown channel type: %s", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "only port forwarding allowed")
			continue
		}

		// Step 2: Parse direct-tcpip extra data
		targetHost, targetPort, err := parseDirectTCPIPExtra(newChannel.ExtraData())
		if err != nil {
			log.Printf("HandleChannels: %v", err)
			newChannel.Reject(ssh.Prohibited, err.Error())
			continue
		}

		// Step 3: Accept the channel
		ch, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("HandleChannels: Error accepting channel: %v", err)
			continue
		}
		go ssh.DiscardRequests(reqs)

		// Step 4: Handle forwarding in a goroutine
		go handlePortForwarding(targetHost, targetPort, ch)
	}
}

// isDirectTCPIPChannel reports whether the provided SSH channel is of type "direct-tcpip".
//
// Parameters:
//   - newChannel: The SSH NewChannel to inspect.
//
// Returns:
//   - bool: true if the channel type is "direct-tcpip", false otherwise.
func isDirectTCPIPChannel(newChannel ssh.NewChannel) bool {
	return newChannel.ChannelType() == "direct-tcpip"
}

// parseDirectTCPIPExtra extracts the target host and port from the extra data of a "direct-tcpip" SSH channel request.
//
// Parameters:
//   - extra: The extra data payload from the SSH NewChannel request.
//
// Returns:
//   - string: The target host requested for forwarding.
//   - uint32: The target port requested for forwarding.
//   - error:  An error if the extra data is malformed or incomplete.
func parseDirectTCPIPExtra(extra []byte) (string, uint32, error) {
	if len(extra) < 4 {
		return "", 0, fmt.Errorf("invalid direct-tcpip request: insufficient data for host length")
	}
	l := int(binary.BigEndian.Uint32(extra[:4]))
	if len(extra) < 4+l+4 {
		return "", 0, fmt.Errorf("invalid direct-tcpip request: insufficient data for host and port")
	}
	targetHost := string(extra[4 : 4+l])
	portOffset := 4 + l
	targetPort := binary.BigEndian.Uint32(extra[portOffset : portOffset+4])
	return targetHost, targetPort, nil
}

// handlePortForwarding establishes a TCP connection to the specified target and relays data between the SSH channel and the target connection.
//
// Parameters:
//   - targetHost: The destination host to connect to.
//   - targetPort: The destination port to connect to.
//   - ch:         The SSH channel to relay data from/to.
//
// This function ensures proper cleanup of the SSH channel and logs any connection errors.
func handlePortForwarding(targetHost string, targetPort uint32, ch ssh.Channel) {
	defer ch.Close()
	addr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
	targetConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("HandleChannels: Error connecting to target %s: %v", addr, err)
		return
	}
	ForwardData(ch, targetConn, addr)
}

// Server functions
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
