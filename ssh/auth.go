// Package ssh provides authentication mechanisms for the SSH server, including PAM integration.
package ssh

import (
	"fmt"
	"log"

	pam "github.com/msteinert/pam/v2"
	"golang.org/x/crypto/ssh"
)

// PAMAuth authenticates a user using PAM (Pluggable Authentication Modules).
// It returns true if authentication succeeds, false otherwise.
// This function is used internally for password-based authentication.
func PAMAuth(user, password string) bool {
	// Start PAM authentication session with callback for password prompt.
	t, err := pam.StartFunc("sshd", user, func(s pam.Style, msg string) (string, error) {
		// Handle different PAM prompt styles.
		switch s {
		case pam.PromptEchoOff:
			// Password prompt (hidden input).
			return password, nil
		case pam.TextInfo:
			// Informational message, no input needed.
			return "", nil
		default:
			// Any other prompt, return empty.
			return "", nil
		}
	})
	if err != nil {
		// PAM session failed to start.
		log.Printf("pamAuth: PAM error for user '%s'", user)
		return false
	}
	// Attempt authentication with PAM.
	if err := t.Authenticate(0); err != nil {
		return false
	}
	return true
}

// PasswordAuth is an ssh.PasswordCallback for PAM authentication.
// It validates the provided credentials using PAMAuth and returns permissions or an error.
// Used by the SSH server to authenticate incoming connections.
func PasswordAuth(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if PAMAuth(c.User(), string(password)) {
		return nil, nil
	}
	return nil, fmt.Errorf("invalid credentials")
}
