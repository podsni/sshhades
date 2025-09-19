package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsValidKeyPath(t *testing.T) {
	testCases := []struct {
		path     string
		expected bool
	}{
		// Valid paths
		{"~/.ssh/id_rsa", true},
		{"~/.ssh/id_ed25519", true},
		{"~/.ssh/id_ecdsa", true},
		{"~/.ssh/id_dsa", true},
		{"~/.ssh/id_rsa.pub", true},
		{"~/.ssh/id_ed25519.pub", true},
		{"~/.ssh/my_key.key", true},
		{"~/.ssh/custom.pub", true},
		{"id_custom", true},
		
		// Invalid paths
		{"~/.ssh/../etc/passwd", false},
		{"../../../etc/passwd", false},
		{"~/.ssh/config", false},
		{"~/.ssh/known_hosts", false},
	}
	
	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			result := IsValidKeyPath(tc.path)
			if result != tc.expected {
				t.Errorf("IsValidKeyPath(%s) = %v, want %v", tc.path, result, tc.expected)
			}
		})
	}
}

func TestIsValidSSHKey(t *testing.T) {
	testCases := []struct {
		name     string
		data     string
		expected bool
	}{
		// Valid public keys
		{
			name:     "RSA public key",
			data:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
			expected: true,
		},
		{
			name:     "Ed25519 public key",
			data:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
			expected: true,
		},
		{
			name:     "ECDSA public key",
			data:     "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI...",
			expected: true,
		},
		
		// Valid private keys
		{
			name:     "RSA private key",
			data:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
			expected: true,
		},
		{
			name:     "OpenSSH private key",
			data:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn\n-----END OPENSSH PRIVATE KEY-----",
			expected: true,
		},
		
		// Invalid data
		{
			name:     "empty",
			data:     "",
			expected: false,
		},
		{
			name:     "random text",
			data:     "This is not an SSH key",
			expected: false,
		},
		{
			name:     "partial key",
			data:     "ssh-rsa",
			expected: true, // This passes basic validation
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidSSHKey([]byte(tc.data))
			if result != tc.expected {
				t.Errorf("IsValidSSHKey(%s) = %v, want %v", tc.name, result, tc.expected)
			}
		})
	}
}

func TestDetectKeyType(t *testing.T) {
	testCases := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "RSA public key",
			data:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
			expected: "rsa",
		},
		{
			name:     "Ed25519 public key",
			data:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
			expected: "ed25519",
		},
		{
			name:     "ECDSA public key",
			data:     "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI...",
			expected: "ecdsa",
		},
		{
			name:     "DSA public key",
			data:     "ssh-dss AAAAB3NzaC1kc3MAAACBAO...",
			expected: "dsa",
		},
		{
			name:     "RSA private key",
			data:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
			expected: "rsa",
		},
		{
			name:     "EC private key",
			data:     "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEII...",
			expected: "ecdsa",
		},
		{
			name:     "OpenSSH Ed25519 private key",
			data:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBed25519...",
			expected: "ed25519",
		},
		{
			name:     "OpenSSH private key",
			data:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn...",
			expected: "openssh",
		},
		{
			name:     "unknown format",
			data:     "This is not a key",
			expected: "unknown",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := DetectKeyType([]byte(tc.data))
			if result != tc.expected {
				t.Errorf("DetectKeyType(%s) = %s, want %s", tc.name, result, tc.expected)
			}
		})
	}
}

func TestIsPrivateKey(t *testing.T) {
	testCases := []struct {
		name     string
		data     string
		expected bool
	}{
		{
			name:     "RSA private key",
			data:     "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
			expected: true,
		},
		{
			name:     "OpenSSH private key",
			data:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA...",
			expected: true,
		},
		{
			name:     "EC private key",
			data:     "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEII...",
			expected: true,
		},
		{
			name:     "RSA public key",
			data:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
			expected: false,
		},
		{
			name:     "Ed25519 public key",
			data:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
			expected: false,
		},
		{
			name:     "random text",
			data:     "This is not a key",
			expected: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsPrivateKey([]byte(tc.data))
			if result != tc.expected {
				t.Errorf("IsPrivateKey(%s) = %v, want %v", tc.name, result, tc.expected)
			}
		})
	}
}

func TestReadKeyFile(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	
	// Create a test key file
	keyContent := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbJ8iGxVsyEL2+Y9b2k1Q2b3J8gJ9X4KqN6y8X5s3Jq test@example.com"
	keyPath := filepath.Join(tempDir, "id_ed25519.pub")
	
	err := os.WriteFile(keyPath, []byte(keyContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test key file: %v", err)
	}
	
	// Test reading the key file
	data, err := ReadKeyFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}
	
	if string(data) != keyContent {
		t.Errorf("Read content doesn't match written content")
	}
	
	// Test reading non-existent file
	_, err = ReadKeyFile(filepath.Join(tempDir, "nonexistent"))
	if err == nil {
		t.Error("Should fail when reading non-existent file")
	}
	
	// Test with invalid path
	_, err = ReadKeyFile("../../../etc/passwd")
	if err == nil {
		t.Error("Should fail with invalid path")
	}
}

func TestWriteKeyFile(t *testing.T) {
	tempDir := t.TempDir()
	
	// Test writing private key
	privateKeyContent := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest private key content\n-----END OPENSSH PRIVATE KEY-----")
	privatePath := filepath.Join(tempDir, "id_test")
	
	err := WriteKeyFile(privatePath, privateKeyContent, true)
	if err != nil {
		t.Fatalf("Failed to write private key: %v", err)
	}
	
	// Check file was created with correct permissions
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatalf("Failed to stat private key file: %v", err)
	}
	
	if info.Mode().Perm() != 0600 {
		t.Errorf("Private key file has wrong permissions: %o, want 0600", info.Mode().Perm())
	}
	
	// Test writing public key
	publicKeyContent := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbJ8iGxVsyEL2+Y9b2k1Q2b3J8gJ9X4KqN6y8X5s3Jq test@example.com")
	publicPath := filepath.Join(tempDir, "id_test.pub")
	
	err = WriteKeyFile(publicPath, publicKeyContent, false)
	if err != nil {
		t.Fatalf("Failed to write public key: %v", err)
	}
	
	// Check file was created with correct permissions
	info, err = os.Stat(publicPath)
	if err != nil {
		t.Fatalf("Failed to stat public key file: %v", err)
	}
	
	if info.Mode().Perm() != 0644 {
		t.Errorf("Public key file has wrong permissions: %o, want 0644", info.Mode().Perm())
	}
}