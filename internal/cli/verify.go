package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sshhades/sshhades/internal/crypto"
	"github.com/sshhades/sshhades/internal/storage"
)

type verifyFlags struct {
	input string
}

func newVerifyCommand() *cobra.Command {
	flags := &verifyFlags{}

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify encrypted file integrity",
		Long: `Verify the integrity and format of an encrypted SSH key file.
This command checks the file format, metadata, and cryptographic parameters
without requiring the passphrase.`,
		Example: `  # Verify an encrypted file
  sshhades verify --input ~/backups/id_ed25519.enc
  
  # Verify multiple files
  sshhades verify -i file1.enc
  sshhades verify -i file2.enc`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(flags)
		},
	}

	cmd.Flags().StringVarP(&flags.input, "input", "i", "", "Path to encrypted file to verify (required)")
	cmd.MarkFlagRequired("input")

	return cmd
}

func runVerify(flags *verifyFlags) error {
	// Validate input path
	if err := storage.ValidatePath(flags.input); err != nil {
		return fmt.Errorf("invalid input path: %w", err)
	}

	// Check if file exists
	if !storage.FileExists(flags.input) {
		return fmt.Errorf("file not found: %s", flags.input)
	}

	fmt.Printf("Verifying encrypted file: %s\n\n", flags.input)

	// Load encrypted file
	encFile, err := storage.LoadEncryptedFile(flags.input)
	if err != nil {
		return fmt.Errorf("failed to load encrypted file: %w", err)
	}

	// Validate encrypted file format
	if err := crypto.ValidateEncryptedFile(encFile); err != nil {
		fmt.Printf("❌ Validation failed: %v\n", err)
		return nil
	}

	// File is valid, show details
	fmt.Println("✓ File format validation passed")
	fmt.Println()

	// Display file information
	fmt.Println("File Information:")
	fmt.Printf("  Version: %s\n", encFile.Header.Version)
	fmt.Printf("  Algorithm: %s\n", encFile.Header.Algorithm)
	fmt.Printf("  KDF: %s\n", encFile.Header.KDF)
	fmt.Printf("  KDF Iterations: %d\n", encFile.Header.Iterations)
	fmt.Printf("  KDF Memory: %d MB\n", encFile.Header.Memory)
	fmt.Printf("  KDF Threads: %d\n", encFile.Header.Threads)
	fmt.Printf("  Created: %s\n", encFile.Header.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	
	if encFile.Header.Comment != "" {
		fmt.Printf("  Comment: %s\n", encFile.Header.Comment)
	}

	fmt.Println()
	fmt.Println("Cryptographic Parameters:")
	fmt.Printf("  Salt length: %d bytes\n", len(encFile.Salt))
	fmt.Printf("  Nonce length: %d bytes\n", len(encFile.Nonce))
	fmt.Printf("  Ciphertext length: %d bytes\n", len(encFile.Ciphertext))
	fmt.Printf("  Authentication tag length: %d bytes\n", len(encFile.Tag))

	// Get absolute path for display
	absPath, _ := filepath.Abs(flags.input)
	fmt.Printf("\n✓ File %s is a valid encrypted SSH key backup\n", absPath)

	return nil
}