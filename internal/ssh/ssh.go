package ssh

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// KeyInfo holds information about an SSH key
type KeyInfo struct {
	Path        string
	Type        string // e.g., "ed25519", "rsa", "ecdsa"
	Comment     string
	Size        int64
	HasPrivate  bool
	HasPublic   bool
}

// ReadKeyFile reads an SSH key file and returns its contents
func ReadKeyFile(path string) ([]byte, error) {
	// Validate path
	if !IsValidKeyPath(path) {
		return nil, fmt.Errorf("invalid key path: %s", path)
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Validate it looks like an SSH key
	if !IsValidSSHKey(data) {
		return nil, fmt.Errorf("file does not appear to be a valid SSH key")
	}

	return data, nil
}

// WriteKeyFile writes SSH key data to a file with appropriate permissions
func WriteKeyFile(path string, data []byte, isPrivate bool) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Set appropriate permissions
	var perm fs.FileMode = 0644 // Public key permissions
	if isPrivate {
		perm = 0600 // Private key permissions
	}

	// Write file
	err := os.WriteFile(path, data, perm)
	if err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// IsValidKeyPath checks if a path looks like an SSH key path
func IsValidKeyPath(path string) bool {
	// Clean the path
	cleanPath := filepath.Clean(path)
	
	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return false
	}

	// Common SSH key patterns
	basename := filepath.Base(cleanPath)
	validPatterns := []string{
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
		"id_rsa.pub", "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub",
	}

	for _, pattern := range validPatterns {
		if basename == pattern {
			return true
		}
	}

	// Allow custom key names with common extensions
	if strings.HasSuffix(basename, ".pub") || 
	   strings.HasSuffix(basename, ".key") ||
	   strings.HasPrefix(basename, "id_") {
		return true
	}

	return false
}

// IsValidSSHKey performs basic validation on SSH key data
func IsValidSSHKey(data []byte) bool {
	content := strings.TrimSpace(string(data))
	
	// Check for empty content
	if len(content) == 0 {
		return false
	}

	// Public key formats
	publicKeyPrefixes := []string{
		"ssh-rsa",
		"ssh-dss", 
		"ssh-ed25519",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
	}

	// Private key formats
	privateKeyHeaders := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
	}

	// Check if it's a public key
	for _, prefix := range publicKeyPrefixes {
		if strings.HasPrefix(content, prefix) {
			return true
		}
	}

	// Check if it's a private key
	for _, header := range privateKeyHeaders {
		if strings.Contains(content, header) {
			return true
		}
	}

	return false
}

// DetectKeyType attempts to determine the SSH key type from its content
func DetectKeyType(data []byte) string {
	content := strings.TrimSpace(string(data))

	// Public key detection
	if strings.HasPrefix(content, "ssh-rsa") {
		return "rsa"
	}
	if strings.HasPrefix(content, "ssh-ed25519") {
		return "ed25519"
	}
	if strings.HasPrefix(content, "ssh-dss") {
		return "dsa"
	}
	if strings.HasPrefix(content, "ecdsa-sha2-") {
		return "ecdsa"
	}

	// Private key detection
	if strings.Contains(content, "RSA PRIVATE KEY") {
		return "rsa"
	}
	if strings.Contains(content, "EC PRIVATE KEY") {
		return "ecdsa"
	}
	if strings.Contains(content, "DSA PRIVATE KEY") {
		return "dsa"
	}
	if strings.Contains(content, "OPENSSH PRIVATE KEY") {
		// Could be any type, but we'll guess based on common usage
		if strings.Contains(content, "ed25519") {
			return "ed25519"
		}
		return "openssh"
	}

	return "unknown"
}

// IsPrivateKey checks if the data appears to be a private key
func IsPrivateKey(data []byte) bool {
	content := string(data)
	return strings.Contains(content, "PRIVATE KEY")
}

// FindSSHKeys searches for SSH keys in the ~/.ssh directory
func FindSSHKeys(sshDir string) ([]KeyInfo, error) {
	var keys []KeyInfo

	// Default to ~/.ssh if no directory specified
	if sshDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		sshDir = filepath.Join(homeDir, ".ssh")
	}

	// Check if directory exists
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return keys, nil // Return empty list if .ssh doesn't exist
	}

	// Read directory contents
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH directory: %w", err)
	}

	// Process each file
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		path := filepath.Join(sshDir, name)

		// Skip known non-key files
		if strings.HasSuffix(name, ".known_hosts") ||
		   strings.HasSuffix(name, "config") ||
		   strings.HasSuffix(name, ".old") {
			continue
		}

		// Check if it looks like a key file
		if IsValidKeyPath(path) {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Try to read and analyze the key
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			if IsValidSSHKey(data) {
				keyInfo := KeyInfo{
					Path:       path,
					Type:       DetectKeyType(data),
					Size:       info.Size(),
					HasPrivate: IsPrivateKey(data),
					HasPublic:  !IsPrivateKey(data),
				}
				keys = append(keys, keyInfo)
			}
		}
	}

	return keys, nil
}