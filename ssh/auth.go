package ssh

import (
	"fmt"
	"log"

	pam "github.com/msteinert/pam/v2"
	"golang.org/x/crypto/ssh"
)

// pamAuth authenticates a user using PAM.
func pamAuth(user, password string) bool {
	t, err := pam.StartFunc("sshd", user, func(s pam.Style, msg string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return password, nil
		case pam.TextInfo:
			return "", nil
		default:
			return "", nil
		}
	})
	if err != nil {
		log.Printf("pamAuth: PAM error for user '%s'", user)
		return false
	}
	if err := t.Authenticate(0); err != nil {
		return false
	}
	return true
}

// PasswordAuthCallback is an ssh.PasswordCallback for PAM authentication.
func PasswordAuthCallback(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if pamAuth(c.User(), string(password)) {
		return nil, nil
	}
	return nil, fmt.Errorf("invalid credentials")
}
