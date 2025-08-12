// Package main is the entry point for the ssh-ify proxy application.
// It initializes and starts the tunnel proxy server or runs user management commands.
package main

import (
	"fmt"
	"os"

	tunnel "ssh-ify/tunnel"
	"ssh-ify/usermgmt"
)

// main initializes and starts the tunnel proxy server or runs user management.
func main() {
	// Check for command line arguments
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "user-mgmt", "users", "manage-users":
			// Run user management CLI
			um := usermgmt.NewManager("")
			um.RunUserManagementCLI()
			return

		case "add-user":
			if len(os.Args) != 4 {
				fmt.Println("Usage: ssh-ify add-user <username> <password>")
				os.Exit(1)
			}
			um := usermgmt.NewManager("")
			if err := um.AddUserDirect(os.Args[2], os.Args[3]); err != nil {
				fmt.Printf("Error adding user: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("User '%s' added successfully!\n", os.Args[2])
			return

		case "remove-user":
			if len(os.Args) != 3 {
				fmt.Println("Usage: ssh-ify remove-user <username>")
				os.Exit(1)
			}
			um := usermgmt.NewManager("")
			if err := um.RemoveUser(os.Args[2]); err != nil {
				fmt.Printf("Error removing user: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("User '%s' removed successfully!\n", os.Args[2])
			return

		case "list-users":
			um := usermgmt.NewManager("")
			um.ListUsers()
			return

		case "enable-user":
			if len(os.Args) != 3 {
				fmt.Println("Usage: ssh-ify enable-user <username>")
				os.Exit(1)
			}
			um := usermgmt.NewManager("")
			if err := um.EnableUser(os.Args[2]); err != nil {
				fmt.Printf("Error enabling user: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("User '%s' enabled successfully!\n", os.Args[2])
			return

		case "disable-user":
			if len(os.Args) != 3 {
				fmt.Println("Usage: ssh-ify disable-user <username>")
				os.Exit(1)
			}
			um := usermgmt.NewManager("")
			if err := um.DisableUser(os.Args[2]); err != nil {
				fmt.Printf("Error disabling user: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("User '%s' disabled successfully!\n", os.Args[2])
			return

		case "help", "-h", "--help":
			printUsage()
			return

		default:
			fmt.Printf("Unknown command: %s\n", os.Args[1])
			printUsage()
			os.Exit(1)
		}
	}

	// Start the proxy server defined in the tunnel package.
	tunnel.StartProxyServer()
}

// printUsage displays usage information.
func printUsage() {
	fmt.Println("SSH-ify - SSH Tunnel Proxy Server")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  ssh-ify                           - Start the proxy server")
	fmt.Println("  ssh-ify user-mgmt                 - Interactive user management")
	fmt.Println("  ssh-ify add-user <user> <pass>    - Add a user")
	fmt.Println("  ssh-ify remove-user <user>        - Remove a user")
	fmt.Println("  ssh-ify list-users                - List all users")
	fmt.Println("  ssh-ify enable-user <user>        - Enable a user")
	fmt.Println("  ssh-ify disable-user <user>       - Disable a user")
	fmt.Println("  ssh-ify help                      - Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  ssh-ify add-user alice mypassword")
	fmt.Println("  ssh-ify remove-user alice")
	fmt.Println("  ssh-ify user-mgmt")
}
