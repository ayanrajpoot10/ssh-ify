// Package config provides configuration directory management for ssh-ify.
package config

import (
	"os"
	"path/filepath"
)

// GetConfigDir returns the configuration directory for ssh-ify.
// It follows platform-specific conventions:
// - Windows: %APPDATA%\ssh-ify
// - Unix-like: $XDG_CONFIG_HOME/ssh-ify or $HOME/.config/ssh-ify
func GetConfigDir() (string, error) {
	var configDir string

	// Check for XDG_CONFIG_HOME first (cross-platform standard)
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		configDir = filepath.Join(xdgConfig, "ssh-ify")
	} else if appData := os.Getenv("APPDATA"); appData != "" {
		// Windows: use APPDATA
		configDir = filepath.Join(appData, "ssh-ify")
	} else if homeDir, err := os.UserHomeDir(); err == nil {
		// Unix-like: use ~/.config/ssh-ify
		configDir = filepath.Join(homeDir, ".config", "ssh-ify")
	} else {
		return "", err
	}

	// Ensure the directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", err
	}

	return configDir, nil
}

// GetUserDBPath returns the full path to the user database file in the config directory.
func GetUserDBPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "users.json"), nil
}
