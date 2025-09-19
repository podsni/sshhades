package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDFParams holds parameters for Argon2id key derivation
type KDFParams struct {
	Iterations uint32 // Number of iterations
	Memory     uint32 // Memory usage in MB
	Threads    uint8  // Number of threads
	KeyLength  uint32 // Derived key length in bytes
}

// DefaultKDFParams returns secure default parameters for Argon2id
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Iterations: 100000, // 100k iterations
		Memory:     64,     // 64 MB
		Threads:    4,      // 4 threads
		KeyLength:  32,     // 32 bytes = 256 bits for AES-256
	}
}

// FastKDFParams returns faster parameters for development/testing
func FastKDFParams() KDFParams {
	return KDFParams{
		Iterations: 1000,   // Much faster for development
		Memory:     8,      // Lower memory usage
		Threads:    1,      // Single thread
		KeyLength:  32,     // 32 bytes = 256 bits
	}
}

// DeriveKey derives an AES key from a passphrase using Argon2id
func DeriveKey(passphrase []byte, salt []byte, params KDFParams) []byte {
	return argon2.IDKey(
		passphrase,
		salt,
		params.Iterations,
		params.Memory*1024, // Convert MB to KB
		params.Threads,
		params.KeyLength,
	)
}

// GenerateSalt creates a cryptographically secure random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32) // 256-bit salt
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// GenerateNonce creates a cryptographically secure random nonce for AES-GCM
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 12) // 96-bit nonce for AES-GCM
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// ClearBytes securely clears sensitive data from memory
func ClearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}