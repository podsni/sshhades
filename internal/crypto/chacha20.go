package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptChaCha20 encrypts data using ChaCha20-Poly1305
func EncryptChaCha20(data []byte, passphrase []byte, params KDFParams) (*EncryptionResult, error) {
	// Generate salt for KDF
	salt, err := GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from passphrase (ChaCha20 uses 32-byte keys)
	key := DeriveKey(passphrase, salt, params)
	defer ClearBytes(key) // Clear key from memory when done

	// Create ChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Generate nonce (ChaCha20-Poly1305 uses 12-byte nonces)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Split ciphertext and tag
	tagSize := aead.Overhead()
	if len(ciphertext) < tagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	actualCiphertext := ciphertext[:len(ciphertext)-tagSize]
	tag := ciphertext[len(ciphertext)-tagSize:]

	return &EncryptionResult{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: actualCiphertext,
		Tag:        tag,
	}, nil
}

// DecryptChaCha20 decrypts data using ChaCha20-Poly1305
func DecryptChaCha20(salt, nonce, ciphertext, tag []byte, passphrase []byte, params KDFParams) ([]byte, error) {
	// Derive key from passphrase
	key := DeriveKey(passphrase, salt, params)
	defer ClearBytes(key) // Clear key from memory when done

	// Create ChaCha20-Poly1305 AEAD
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Reconstruct full ciphertext with tag
	fullCiphertext := append(ciphertext, tag...)

	// Decrypt data
	plaintext, err := aead.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	return plaintext, nil
}