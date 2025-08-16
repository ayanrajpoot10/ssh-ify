package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

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
