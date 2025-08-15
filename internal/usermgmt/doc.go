// Package usermgmt provides user account management and authentication for ssh-ify.
//
// Features:
//   - Thread-safe user database with persistent storage (JSON file)
//   - Secure password hashing (bcrypt) and credential verification
//   - User account operations: add, remove, enable, disable, update password
//   - Backup and restore of user database
//   - Command-line interface (CLI) for interactive user management
//   - Integration with SSH authentication (see internal/ssh)
//
// Usage:
//  1. Create a UserDB with NewUserDB, or use Manager for CLI tools
//  2. Use AddUser, RemoveUser, UpdatePassword, EnableUser, DisableUser for account management
//  3. Use Authenticate for login verification
//  4. Use BackupDB to create backups of the user database
//  5. Run RunUserManagementCLI for an interactive management shell
//
// This package is intended for use by the ssh-ify server and its administrative tools.
package usermgmt
