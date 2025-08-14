// Package ssh provides authentication mechanisms for the SSH server using a custom user database.
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

// InitializeAuth initializes the authentication system with a user database.
// This must be called before using any authentication functions.
func InitializeAuth(dbPath string) error {
	userDB = usermgmt.NewUserDB(dbPath)
	return nil
}

// GetUserDB returns the global user database instance.
// Returns nil if InitializeAuth hasn't been called.
func GetUserDB() *usermgmt.UserDB {
	return userDB
}

// PasswordAuth is an ssh.PasswordCallback for custom authentication.
// It validates the provided credentials using the user database and returns permissions or an error.
// Used by the SSH server to authenticate incoming connections.
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
