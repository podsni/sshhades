package crypto

import (
	"bytes"
	"testing"

	"github.com/sshhades/sshhades/pkg/format"
)

func TestDefaultKDFParams(t *testing.T) {
	params := DefaultKDFParams()
	
	if params.Iterations != 100000 {
		t.Errorf("Expected iterations 100000, got %d", params.Iterations)
	}
	
	if params.Memory != 64 {
		t.Errorf("Expected memory 64, got %d", params.Memory)
	}
	
	if params.Threads != 4 {
		t.Errorf("Expected threads 4, got %d", params.Threads)
	}
	
	if params.KeyLength != 32 {
		t.Errorf("Expected key length 32, got %d", params.KeyLength)
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate second salt: %v", err)
	}
	
	if len(salt1) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(salt1))
	}
	
	if bytes.Equal(salt1, salt2) {
		t.Error("Generated salts should be different")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	
	nonce2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to generate second nonce: %v", err)
	}
	
	if len(nonce1) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(nonce1))
	}
	
	if bytes.Equal(nonce1, nonce2) {
		t.Error("Generated nonces should be different")
	}
}

func TestDeriveKey(t *testing.T) {
	passphrase := []byte("test passphrase")
	salt := []byte("test salt for key derivation function")
	// Use faster parameters for testing
	params := KDFParams{
		Iterations: 1000,  // Much lower for testing
		Memory:     8,     // Lower memory
		Threads:    1,     // Single thread
		KeyLength:  32,
	}
	
	key1 := DeriveKey(passphrase, salt, params)
	key2 := DeriveKey(passphrase, salt, params)
	
	if len(key1) != int(params.KeyLength) {
		t.Errorf("Expected key length %d, got %d", params.KeyLength, len(key1))
	}
	
	if !bytes.Equal(key1, key2) {
		t.Error("Same inputs should produce same key")
	}
	
	// Test with different salt
	differentSalt := []byte("different salt for key derivation")
	key3 := DeriveKey(passphrase, differentSalt, params)
	
	if bytes.Equal(key1, key3) {
		t.Error("Different salts should produce different keys")
	}
}

func TestClearBytes(t *testing.T) {
	data := []byte("sensitive data")
	original := make([]byte, len(data))
	copy(original, data)
	
	ClearBytes(data)
	
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d not cleared: %d", i, b)
		}
	}
	
	// Ensure original wasn't affected
	if string(original) != "sensitive data" {
		t.Error("Original data was unexpectedly modified")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Test data
	originalData := []byte("This is a test SSH private key content")
	passphrase := []byte("strong passphrase for testing")
	// Use faster parameters for testing
	params := KDFParams{
		Iterations: 1000,  // Much lower for testing
		Memory:     8,     // Lower memory
		Threads:    1,     // Single thread
		KeyLength:  32,
	}
	
	// Encrypt
	result, err := Encrypt(originalData, passphrase, params)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	// Validate encryption result
	if len(result.Salt) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(result.Salt))
	}
	
	if len(result.Nonce) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(result.Nonce))
	}
	
	if len(result.Tag) != 16 {
		t.Errorf("Expected tag length 16, got %d", len(result.Tag))
	}
	
	if len(result.Ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}
	
	// Create encrypted file structure
	header := format.DefaultHeader()
	header.Iterations = params.Iterations
	header.Memory = params.Memory
	header.Threads = params.Threads
	
	encFile := &format.EncryptedFile{
		Header:     header,
		Salt:       result.Salt,
		Nonce:      result.Nonce,
		Ciphertext: result.Ciphertext,
		Tag:        result.Tag,
	}
	
	// Decrypt
	decryptedData, err := Decrypt(encFile, passphrase)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	// Verify round trip
	if !bytes.Equal(originalData, decryptedData) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestDecryptWithWrongPassphrase(t *testing.T) {
	// Encrypt with one passphrase
	originalData := []byte("secret data")
	correctPassphrase := []byte("correct passphrase")
	wrongPassphrase := []byte("wrong passphrase")
	// Use faster parameters for testing
	params := KDFParams{
		Iterations: 1000,  // Much lower for testing
		Memory:     8,     // Lower memory
		Threads:    1,     // Single thread
		KeyLength:  32,
	}
	
	result, err := Encrypt(originalData, correctPassphrase, params)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	header := format.DefaultHeader()
	header.Iterations = params.Iterations
	header.Memory = params.Memory
	header.Threads = params.Threads
	
	encFile := &format.EncryptedFile{
		Header:     header,
		Salt:       result.Salt,
		Nonce:      result.Nonce,
		Ciphertext: result.Ciphertext,
		Tag:        result.Tag,
	}
	
	// Try to decrypt with wrong passphrase
	_, err = Decrypt(encFile, wrongPassphrase)
	if err == nil {
		t.Error("Decryption should fail with wrong passphrase")
	}
}

func TestValidateEncryptedFile(t *testing.T) {
	// Valid file
	header := format.DefaultHeader()
	validFile := &format.EncryptedFile{
		Header:     header,
		Salt:       make([]byte, 32),
		Nonce:      make([]byte, 12),
		Ciphertext: []byte("test ciphertext"),
		Tag:        make([]byte, 16),
	}
	
	if err := ValidateEncryptedFile(validFile); err != nil {
		t.Errorf("Valid file should pass validation: %v", err)
	}
	
	// Test various invalid cases
	testCases := []struct {
		name string
		file *format.EncryptedFile
	}{
		{
			name: "wrong version",
			file: &format.EncryptedFile{
				Header:     format.Header{Version: "2.0", Algorithm: "AES-256-GCM", KDF: "Argon2id"},
				Salt:       make([]byte, 32),
				Nonce:      make([]byte, 12),
				Ciphertext: []byte("test"),
				Tag:        make([]byte, 16),
			},
		},
		{
			name: "wrong algorithm",
			file: &format.EncryptedFile{
				Header:     format.Header{Version: format.Version, Algorithm: "AES-128-CBC", KDF: "Argon2id"},
				Salt:       make([]byte, 32),
				Nonce:      make([]byte, 12),
				Ciphertext: []byte("test"),
				Tag:        make([]byte, 16),
			},
		},
		{
			name: "wrong KDF",
			file: &format.EncryptedFile{
				Header:     format.Header{Version: format.Version, Algorithm: "AES-256-GCM", KDF: "scrypt"},
				Salt:       make([]byte, 32),
				Nonce:      make([]byte, 12),
				Ciphertext: []byte("test"),
				Tag:        make([]byte, 16),
			},
		},
		{
			name: "wrong salt length",
			file: &format.EncryptedFile{
				Header:     header,
				Salt:       make([]byte, 16),
				Nonce:      make([]byte, 12),
				Ciphertext: []byte("test"),
				Tag:        make([]byte, 16),
			},
		},
		{
			name: "wrong nonce length",
			file: &format.EncryptedFile{
				Header:     header,
				Salt:       make([]byte, 32),
				Nonce:      make([]byte, 16),
				Ciphertext: []byte("test"),
				Tag:        make([]byte, 16),
			},
		},
		{
			name: "wrong tag length",
			file: &format.EncryptedFile{
				Header:     header,
				Salt:       make([]byte, 32),
				Nonce:      make([]byte, 12),
				Ciphertext: []byte("test"),
				Tag:        make([]byte, 8),
			},
		},
		{
			name: "empty ciphertext",
			file: &format.EncryptedFile{
				Header:     header,
				Salt:       make([]byte, 32),
				Nonce:      make([]byte, 12),
				Ciphertext: []byte{},
				Tag:        make([]byte, 16),
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateEncryptedFile(tc.file); err == nil {
				t.Errorf("Invalid file should fail validation: %s", tc.name)
			}
		})
	}
}