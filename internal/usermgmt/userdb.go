// Package usermgmt provides user database management for SSH authentication.
package usermgmt

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a user account in the system.
type User struct {
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
	Enabled      bool       `json:"enabled"`
}

// UserDB manages user accounts with thread-safe operations.
type UserDB struct {
	users    map[string]*User
	filePath string
	mutex    sync.RWMutex
}

// NewUserDB creates a new user database instance.
// If dbPath is empty, it uses "users.json" in the current directory.
func NewUserDB(dbPath string) *UserDB {
	if dbPath == "" {
		dbPath = "users.json"
	}

	db := &UserDB{
		users:    make(map[string]*User),
		filePath: dbPath,
	}

	// Load existing users from file
	db.loadFromFile()

	return db
}

// hashPassword creates a bcrypt hash of the password.
func (db *UserDB) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// verifyPassword checks if the provided password matches the stored hash.
func (db *UserDB) verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// AddUser creates a new user account.
func (db *UserDB) AddUser(username, password string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Check if user already exists
	if _, exists := db.users[username]; exists {
		return fmt.Errorf("user '%s' already exists", username)
	}

	// Validate input
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(password) < 4 {
		return fmt.Errorf("password must be at least 4 characters long")
	}

	// Hash password
	hash, err := db.hashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Create user
	user := &User{
		Username:     username,
		PasswordHash: hash,
		CreatedAt:    time.Now(),
		Enabled:      true,
	}

	db.users[username] = user

	// Save to file
	if err := db.saveToFile(); err != nil {
		// Rollback
		delete(db.users, username)
		return fmt.Errorf("failed to save user database: %v", err)
	}

	return nil
}

// RemoveUser deletes a user account.
func (db *UserDB) RemoveUser(username string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if _, exists := db.users[username]; !exists {
		return fmt.Errorf("user '%s' does not exist", username)
	}

	delete(db.users, username)

	// Save to file
	if err := db.saveToFile(); err != nil {
		return fmt.Errorf("failed to save user database: %v", err)
	}

	return nil
}

// UpdatePassword changes a user's password.
func (db *UserDB) UpdatePassword(username, newPassword string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	user, exists := db.users[username]
	if !exists {
		return fmt.Errorf("user '%s' does not exist", username)
	}

	if len(newPassword) < 4 {
		return fmt.Errorf("password must be at least 4 characters long")
	}

	// Hash password
	hash, err := db.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Update user
	user.PasswordHash = hash

	// Save to file
	if err := db.saveToFile(); err != nil {
		return fmt.Errorf("failed to save user database: %v", err)
	}

	return nil
}

// EnableUser enables a user account.
func (db *UserDB) EnableUser(username string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	user, exists := db.users[username]
	if !exists {
		return fmt.Errorf("user '%s' does not exist", username)
	}

	user.Enabled = true

	// Save to file
	if err := db.saveToFile(); err != nil {
		return fmt.Errorf("failed to save user database: %v", err)
	}

	return nil
}

// DisableUser disables a user account.
func (db *UserDB) DisableUser(username string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	user, exists := db.users[username]
	if !exists {
		return fmt.Errorf("user '%s' does not exist", username)
	}

	user.Enabled = false

	// Save to file
	if err := db.saveToFile(); err != nil {
		return fmt.Errorf("failed to save user database: %v", err)
	}

	return nil
}

// Authenticate verifies user credentials.
func (db *UserDB) Authenticate(username, password string) bool {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	user, exists := db.users[username]
	if !exists || !user.Enabled {
		return false
	}

	if db.verifyPassword(password, user.PasswordHash) {
		return true
	}

	return false
}

// ListUsers returns a list of all usernames.
func (db *UserDB) ListUsers() []string {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	users := make([]string, 0, len(db.users))
	for username := range db.users {
		users = append(users, username)
	}
	return users
}

// GetUserInfo returns user information (without password hash).
func (db *UserDB) GetUserInfo(username string) (*User, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	user, exists := db.users[username]
	if !exists {
		return nil, fmt.Errorf("user '%s' does not exist", username)
	}

	// Return a copy without the password hash for security
	return &User{
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		LastLogin: user.LastLogin,
		Enabled:   user.Enabled,
	}, nil
}

// saveToFile saves the user database to disk.
func (db *UserDB) saveToFile() error {
	data, err := json.MarshalIndent(db.users, "", "  ")
	if err != nil {
		return err
	}

	// Write to temporary file first, then rename for atomic operation
	tempFile := db.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return err
	}

	if err := os.Rename(tempFile, db.filePath); err != nil {
		os.Remove(tempFile) // Clean up temp file
		return err
	}

	return nil
}

// loadFromFile loads the user database from disk.
func (db *UserDB) loadFromFile() error {
	file, err := os.Open(db.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, start with empty database
			return nil
		}
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		// Empty file, start with empty database
		return nil
	}

	return json.Unmarshal(data, &db.users)
}

// BackupDB creates a backup of the user database.
func (db *UserDB) BackupDB(backupPath string) error {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	sourceFile, err := os.Open(db.filePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
