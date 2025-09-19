package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sshhades/sshhades/pkg/format"
)

// SaveEncryptedFile saves an encrypted file to disk
func SaveEncryptedFile(path string, encFile *format.EncryptedFile) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Convert to JSON
	data, err := encFile.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize encrypted file: %w", err)
	}

	// Write to file with restrictive permissions
	err = os.WriteFile(path, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	return nil
}

// LoadEncryptedFile loads an encrypted file from disk
func LoadEncryptedFile(path string) (*format.EncryptedFile, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Parse JSON
	encFile, err := format.FromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted file: %w", err)
	}

	return encFile, nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// CreateBackupPath generates a backup file path with .enc extension
func CreateBackupPath(originalPath, outputDir string) string {
	basename := filepath.Base(originalPath)
	backupName := basename + ".enc"
	
	if outputDir == "" {
		// Use same directory as original file
		dir := filepath.Dir(originalPath)
		return filepath.Join(dir, backupName)
	}
	
	return filepath.Join(outputDir, backupName)
}

// ValidatePath performs security checks on file paths
func ValidatePath(path string) error {
	// Clean the path
	cleanPath := filepath.Clean(path)
	
	// Check for relative path traversal
	if filepath.IsAbs(path) != filepath.IsAbs(cleanPath) {
		return fmt.Errorf("path traversal detected: %s", path)
	}
	
	// Additional security checks can be added here
	return nil
}