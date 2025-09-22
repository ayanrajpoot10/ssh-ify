// Package ssh provides core SSH server functionality for ssh-ify.
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

// CopyWithSSHBuffer performs buffered copying using a pooled buffer.
func CopyWithSSHBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := getSSHBuffer()
	defer putSSHBuffer(buf)
	return io.CopyBuffer(dst, src, *buf)
}

// Authentication functions
// InitializeAuth sets up the global authentication system.
func InitializeAuth(dbPath string) error {
	userDB = usermgmt.NewUserDB(dbPath)
	return nil
}

// GetUserDB returns the global user database instance.
func GetUserDB() *usermgmt.UserDB {
	return userDB
}

// PasswordAuth implements ssh.PasswordCallback for authentication.
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
// NewRSAPrivateKey generates a new RSA private key.
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

// RSAPrivateKeyPEM encodes an RSA private key to PEM format.
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
// NewConfig initializes and returns a new SSH server configuration.
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
// ForwardData relays data bidirectionally between an SSH channel and a target connection.
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

// HandleSSHChannels processes incoming SSH channels for port forwarding.
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

// isDirectTCPIPChannel reports whether the SSH channel is of type "direct-tcpip".
func isDirectTCPIPChannel(newChannel ssh.NewChannel) bool {
	return newChannel.ChannelType() == "direct-tcpip"
}

// parseDirectTCPIPExtra extracts target host and port from direct-tcpip extra data.
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

// handlePortForwarding establishes a TCP connection to the target and relays data.
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
// HandleSSHConnection handles an incoming SSH connection.
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
