// Package ssh provides core SSH server functionality for ssh-ify, including:
//
//   - User authentication (password-based, pluggable via usermgmt)
//   - Host key generation and management (RSA, PEM encoding)
//   - SSH server configuration and version banner customization
//   - Secure connection handling and session management
//   - Port forwarding (direct-tcpip) and channel data relay
//
// Features:
//
//   - Pluggable authentication using a user database (see internal/usermgmt)
//   - Automatic host key generation if not present on disk
//   - Customizable SSH version banner and login banner
//   - Robust handling of SSH channels and port forwarding requests
//   - Utility functions for key creation and PEM encoding
//
// Usage:
//
//  1. Initialize authentication with InitializeAuth (typically at startup)
//  2. Create a server config with NewConfig
//  3. Accept incoming connections and handle them with ServeConn
//  4. Use ServePortForward to process port forwarding channels
//
// This package is intended for use by the ssh-ify server and related internal components.
package ssh
