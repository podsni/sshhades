package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/sshhades/sshhades/pkg/format"
)

// EncryptionResult holds the result of encryption operation
type EncryptionResult struct {
	Salt       []byte
	Nonce      []byte
	Ciphertext []byte
	Tag        []byte
}

// Encrypt encrypts data using the specified algorithm with Argon2id key derivation
func Encrypt(data []byte, passphrase []byte, algorithm string, params KDFParams) (*EncryptionResult, error) {
	switch algorithm {
	case format.AlgorithmAESGCM:
		return EncryptAES(data, passphrase, params)
	case format.AlgorithmChaCha20:
		return EncryptChaCha20(data, passphrase, params)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// EncryptAES encrypts data using AES-256-GCM with Argon2id key derivation
func EncryptAES(data []byte, passphrase []byte, params KDFParams) (*EncryptionResult, error) {
	// Generate salt for KDF
	salt, err := GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive AES key from passphrase
	key := DeriveKey(passphrase, salt, params)
	defer ClearBytes(key) // Clear key from memory when done

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// Split ciphertext and tag (GCM appends tag to ciphertext)
	tagSize := gcm.Overhead()
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

// Decrypt decrypts data using the algorithm specified in the encrypted file
func Decrypt(encFile *format.EncryptedFile, passphrase []byte) ([]byte, error) {
	// Extract KDF parameters from header
	params := KDFParams{
		Iterations: encFile.Header.Iterations,
		Memory:     encFile.Header.Memory,
		Threads:    encFile.Header.Threads,
		KeyLength:  32, // Both AES-256 and ChaCha20 use 32-byte keys
	}

	switch encFile.Header.Algorithm {
	case format.AlgorithmAESGCM:
		return DecryptAES(encFile, passphrase, params)
	case format.AlgorithmChaCha20:
		return DecryptChaCha20(encFile.Salt, encFile.Nonce, encFile.Ciphertext, encFile.Tag, passphrase, params)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", encFile.Header.Algorithm)
	}
}

// DecryptAES decrypts data using AES-256-GCM with Argon2id key derivation
func DecryptAES(encFile *format.EncryptedFile, passphrase []byte, params KDFParams) ([]byte, error) {

	// Derive AES key from passphrase
	key := DeriveKey(passphrase, encFile.Salt, params)
	defer ClearBytes(key) // Clear key from memory when done

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Reconstruct full ciphertext with tag
	fullCiphertext := append(encFile.Ciphertext, encFile.Tag...)

	// Decrypt data
	plaintext, err := gcm.Open(nil, encFile.Nonce, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	return plaintext, nil
}

// ValidateEncryptedFile validates the structure and format of an encrypted file
func ValidateEncryptedFile(encFile *format.EncryptedFile) error {
	if encFile.Header.Version != format.Version {
		return fmt.Errorf("unsupported file version: %s", encFile.Header.Version)
	}

	// Check if algorithm is supported
	switch encFile.Header.Algorithm {
	case format.AlgorithmAESGCM, format.AlgorithmChaCha20:
		// Valid algorithms
	default:
		return fmt.Errorf("unsupported algorithm: %s", encFile.Header.Algorithm)
	}

	if encFile.Header.KDF != "Argon2id" {
		return fmt.Errorf("unsupported KDF: %s", encFile.Header.KDF)
	}

	if len(encFile.Salt) != 32 {
		return fmt.Errorf("invalid salt length: expected 32, got %d", len(encFile.Salt))
	}

	if len(encFile.Nonce) != 12 {
		return fmt.Errorf("invalid nonce length: expected 12, got %d", len(encFile.Nonce))
	}

	if len(encFile.Tag) != 16 {
		return fmt.Errorf("invalid tag length: expected 16, got %d", len(encFile.Tag))
	}

	if len(encFile.Ciphertext) == 0 {
		return fmt.Errorf("empty ciphertext")
	}

	return nil
}