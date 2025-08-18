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
//  2. Create a server config with NewConfig (see config.go)
//  3. Accept incoming connections and handle them with HandleSSHConnection
//  4. Use HandleSSHChannels to process port forwarding channels with buffer pooling
//
// This package is intended for use by the ssh-ify server and related internal components.
package ssh
