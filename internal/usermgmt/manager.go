// Package usermgmt provides command-line tools for user management.
package usermgmt

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

// Manager provides command-line interface for user management.
type Manager struct {
	db *UserDB
}

// NewManager creates a new user manager instance.
func NewManager(dbPath string) *Manager {
	return &Manager{
		db: NewUserDB(dbPath),
	}
}

// GetUserDB returns the underlying UserDB instance for authentication purposes.
func (um *Manager) GetUserDB() *UserDB {
	return um.db
}

// AddUserInteractive prompts for username and password and adds the user.
func (um *Manager) AddUserInteractive() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)

	fmt.Print("Enter password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	password = strings.TrimSpace(password)

	fmt.Print("Confirm password: ")
	confirm, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	confirm = strings.TrimSpace(confirm)

	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}

	return um.db.AddUser(username, password)
}

// AddUserDirect adds a user with provided credentials.
func (um *Manager) AddUserDirect(username, password string) error {
	return um.db.AddUser(username, password)
}

// RemoveUser removes a user account.
func (um *Manager) RemoveUser(username string) error {
	return um.db.RemoveUser(username)
}

// ListUsers displays all users with their information.
func (um *Manager) ListUsers() {
	users := um.db.ListUsers()
	if len(users) == 0 {
		fmt.Println("No users found.")
		return
	}

	fmt.Printf("%-20s %-10s %-20s\n", "Username", "Status", "Created")
	fmt.Println(strings.Repeat("-", 60))

	for _, username := range users {
		user, err := um.db.GetUserInfo(username)
		if err != nil {
			fmt.Printf("%-20s ERROR: %v\n", username, err)
			continue
		}

		status := "Enabled"
		if !user.Enabled {
			status = "Disabled"
		}

		fmt.Printf("%-20s %-10s %-20s\n",
			user.Username,
			status,
			user.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
}

// ChangePasswordInteractive prompts for username and new password.
func (um *Manager) ChangePasswordInteractive() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)

	fmt.Print("Enter new password: ")
	password, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	password = strings.TrimSpace(password)

	fmt.Print("Confirm new password: ")
	confirm, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	confirm = strings.TrimSpace(confirm)

	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}

	return um.db.UpdatePassword(username, password)
}

// EnableUser enables a user account.
func (um *Manager) EnableUser(username string) error {
	return um.db.EnableUser(username)
}

// DisableUser disables a user account.
func (um *Manager) DisableUser(username string) error {
	return um.db.DisableUser(username)
}

// BackupUsers creates a backup of the user database.
func (um *Manager) BackupUsers(backupPath string) error {
	return um.db.BackupDB(backupPath)
}

// PrintHelp displays help information for user management commands.
func (um *Manager) PrintHelp() {
	fmt.Println("User Management Commands:")
	fmt.Println("  add-user           - Add a new user (interactive)")
	fmt.Println("  remove-user <user> - Remove a user")
	fmt.Println("  list-users         - List all users")
	fmt.Println("  change-password    - Change user password (interactive)")
	fmt.Println("  enable-user <user> - Enable a user account")
	fmt.Println("  disable-user <user>- Disable a user account")
	fmt.Println("  backup-users <file>- Backup user database")
	fmt.Println("  help               - Show this help")
}

// CreateDefaultUserFromEnv creates a default user from environment variables if they are set.
// This function checks for SSH_IFY_DEFAULT_USER and SSH_IFY_DEFAULT_PASSWORD environment variables.
// If both are set and the user doesn't already exist, it creates the user automatically.
func (um *Manager) CreateDefaultUserFromEnv() error {
	defaultUser := os.Getenv("SSH_IFY_DEFAULT_USER")
	defaultPassword := os.Getenv("SSH_IFY_DEFAULT_PASSWORD")

	// If environment variables are not set, do nothing
	if defaultUser == "" || defaultPassword == "" {
		return nil
	}

	// Check if user already exists
	users := um.db.ListUsers()
	for _, username := range users {
		if username == defaultUser {
			log.Printf("Default user '%s' already exists, skipping creation", defaultUser)
			return nil
		}
	}

	// Create the default user
	log.Printf("Creating default user '%s' from environment variables", defaultUser)
	if err := um.db.AddUser(defaultUser, defaultPassword); err != nil {
		return fmt.Errorf("failed to create default user '%s': %v", defaultUser, err)
	}

	log.Printf("Successfully created default user '%s'", defaultUser)
	return nil
}

// RunUserManagementCLI runs an interactive user management command-line interface.
func (um *Manager) RunUserManagementCLI() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("SSH-ify User Management")
	fmt.Println("Type 'help' for available commands or 'quit' to exit.")

	for {
		fmt.Print("ssh-ify> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		input = strings.TrimSpace(input)
		parts := strings.Fields(input)

		if len(parts) == 0 {
			continue
		}

		command := parts[0]

		switch command {
		case "quit", "exit":
			fmt.Println("Goodbye!")
			return

		case "help":
			um.PrintHelp()

		case "add-user":
			if err := um.AddUserInteractive(); err != nil {
				fmt.Printf("Error adding user: %v\n", err)
			} else {
				fmt.Println("User added successfully!")
			}

		case "remove-user":
			if len(parts) < 2 {
				fmt.Println("Usage: remove-user <username>")
				continue
			}
			if err := um.RemoveUser(parts[1]); err != nil {
				fmt.Printf("Error removing user: %v\n", err)
			} else {
				fmt.Printf("User '%s' removed successfully!\n", parts[1])
			}

		case "list-users":
			um.ListUsers()

		case "change-password":
			if err := um.ChangePasswordInteractive(); err != nil {
				fmt.Printf("Error changing password: %v\n", err)
			} else {
				fmt.Println("Password changed successfully!")
			}

		case "enable-user":
			if len(parts) < 2 {
				fmt.Println("Usage: enable-user <username>")
				continue
			}
			if err := um.EnableUser(parts[1]); err != nil {
				fmt.Printf("Error enabling user: %v\n", err)
			} else {
				fmt.Printf("User '%s' enabled successfully!\n", parts[1])
			}

		case "disable-user":
			if len(parts) < 2 {
				fmt.Println("Usage: disable-user <username>")
				continue
			}
			if err := um.DisableUser(parts[1]); err != nil {
				fmt.Printf("Error disabling user: %v\n", err)
			} else {
				fmt.Printf("User '%s' disabled successfully!\n", parts[1])
			}

		case "backup-users":
			if len(parts) < 2 {
				fmt.Println("Usage: backup-users <backup-file-path>")
				continue
			}
			if err := um.BackupUsers(parts[1]); err != nil {
				fmt.Printf("Error backing up users: %v\n", err)
			} else {
				fmt.Printf("User database backed up to '%s' successfully!\n", parts[1])
			}

		default:
			fmt.Printf("Unknown command: %s\n", command)
			fmt.Println("Type 'help' for available commands.")
		}
	}
}
