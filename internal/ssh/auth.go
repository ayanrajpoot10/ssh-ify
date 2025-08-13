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

// CustomAuth authenticates a user using the custom user database.
// It returns true if authentication succeeds, false otherwise.
func CustomAuth(user, password string) bool {
	if userDB == nil {
		log.Printf("CustomAuth: user database not initialized")
		return false
	}

	success := userDB.Authenticate(user, password)
	if success {
		log.Printf("CustomAuth: successful login for user '%s'", user)
	} else {
		log.Printf("CustomAuth: failed login attempt for user '%s'", user)
	}

	return success
}

// PasswordAuth is an ssh.PasswordCallback for custom authentication.
// It validates the provided credentials using CustomAuth and returns permissions or an error.
// Used by the SSH server to authenticate incoming connections.
func PasswordAuth(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if CustomAuth(c.User(), string(password)) {
		return nil, nil
	}
	return nil, fmt.Errorf("invalid credentials")
}
