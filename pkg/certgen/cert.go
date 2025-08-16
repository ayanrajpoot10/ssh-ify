// Package certgen provides utilities for generating self-signed X.509 certificates and RSA private keys.
//
// This package is primarily used to create and manage certificates for the ssh-ify proxy server, enabling secure TLS communication.
// It offers functions to generate new certificates and keys, write them to disk in PEM format, and check for their existence.
//
// Typical usage:
//
//	err := certgen.GenerateCert("cert.pem", "key.pem")
//	if err != nil {
//	    log.Fatalf("Failed to generate cert: %v", err)
//	}
package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateCert generates a self-signed X.509 certificate and a 2048-bit RSA private key.
//
// The certificate and key are written to the specified certFile and keyFile paths in PEM format.
// If both files already exist, the function returns early without overwriting them.
//
// Args:
//
//	certFile: Path to the certificate file to create or check.
//	keyFile:  Path to the private key file to create or check.
//
// Returns:
//
//	An error if certificate or key generation fails, or if writing to disk fails.
func GenerateCert(certFile, keyFile string) error {
	// Return early if both cert and key files exist
	if fileExists(certFile) && fileExists(keyFile) {
		return nil
	}

	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Certificate template
	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"ssh-ify"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	if err := writePemToFile(certFile, "CERTIFICATE", derBytes); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key to file
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := writePemToFile(keyFile, "RSA PRIVATE KEY", keyBytes); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// fileExists reports whether the named file exists and is not a directory.
// It returns true if the file exists, false otherwise.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// writePemToFile writes the given bytes as a PEM-encoded block of the specified type to the given filename.
// It creates or truncates the file as needed.
// Returns an error if the file cannot be created or written.
func writePemToFile(filename, pemType string, bytes []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: pemType, Bytes: bytes})
}
