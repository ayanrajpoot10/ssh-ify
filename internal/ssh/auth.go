package ssh

import (
	"fmt"
	"log"

	"ssh-ify/internal/usermgmt"

	"golang.org/x/crypto/ssh"
)

var (
	// Global user database instance
	userDB *usermgmt.UserDB
)

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
