package format

import (
	"encoding/json"
	"time"
)

// Version represents the encrypted file format version
const Version = "1.0"

// Supported algorithms
const (
	AlgorithmAESGCM     = "AES-256-GCM"
	AlgorithmChaCha20   = "ChaCha20-Poly1305"
)

// EncryptedFile represents the structure of an encrypted SSH key file
type EncryptedFile struct {
	// Header contains metadata about the encrypted file
	Header Header `json:"header"`
	
	// Salt is used for key derivation
	Salt []byte `json:"salt"`
	
	// Nonce is the AES-GCM nonce
	Nonce []byte `json:"nonce"`
	
	// Ciphertext contains the encrypted SSH key data
	Ciphertext []byte `json:"ciphertext"`
	
	// Tag is the AES-GCM authentication tag
	Tag []byte `json:"tag"`
}

// Header contains metadata about the encryption
type Header struct {
	// Version of the file format
	Version string `json:"version"`
	
	// Algorithm used for encryption (e.g., "AES-256-GCM")
	Algorithm string `json:"algorithm"`
	
	// KDF is the key derivation function used (e.g., "Argon2id")
	KDF string `json:"kdf"`
	
	// Iterations for the KDF
	Iterations uint32 `json:"iterations"`
	
	// Memory is the memory parameter for Argon2id (in MB)
	Memory uint32 `json:"memory"`
	
	// Threads is the parallelism parameter for Argon2id
	Threads uint8 `json:"threads"`
	
	// Timestamp when the file was created
	Timestamp time.Time `json:"timestamp"`
	
	// Comment is a user-provided description
	Comment string `json:"comment,omitempty"`
}

// DefaultHeader returns a header with secure default values
func DefaultHeader() Header {
	return Header{
		Version:    Version,
		Algorithm:  AlgorithmAESGCM,
		KDF:        "Argon2id",
		Iterations: 100000,  // 100k iterations
		Memory:     64,      // 64 MB
		Threads:    4,       // 4 threads
		Timestamp:  time.Now().UTC(),
	}
}

// FastHeader returns a header with faster parameters for development
func FastHeader() Header {
	return Header{
		Version:    Version,
		Algorithm:  AlgorithmAESGCM,
		KDF:        "Argon2id",
		Iterations: 1000,    // Much faster
		Memory:     8,       // Lower memory
		Threads:    1,       // Single thread
		Timestamp:  time.Now().UTC(),
	}
}

// ToJSON serializes the encrypted file to JSON format
func (ef *EncryptedFile) ToJSON() ([]byte, error) {
	return json.MarshalIndent(ef, "", "  ")
}

// FromJSON deserializes an encrypted file from JSON format
func FromJSON(data []byte) (*EncryptedFile, error) {
	var ef EncryptedFile
	err := json.Unmarshal(data, &ef)
	return &ef, err
}