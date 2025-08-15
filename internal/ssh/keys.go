package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// NewRSAPrivateKey creates a new RSA private key of the specified bit size.
// Returns the generated key or an error if generation or validation fails.
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
// Returns the PEM-encoded byte slice for use in SSH server configuration.
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
