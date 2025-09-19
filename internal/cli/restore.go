package cli

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sshhades/sshhades/internal/crypto"
	"github.com/sshhades/sshhades/internal/ssh"
	"github.com/sshhades/sshhades/internal/storage"
)

type restoreFlags struct {
	input         string
	output        string
	passphraseEnv string
	force         bool
}

func newRestoreCommand() *cobra.Command {
	flags := &restoreFlags{}

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Decrypt and restore an SSH key",
		Long: `Decrypt an encrypted SSH key file and restore it to the filesystem.
The original SSH key permissions will be restored (0600 for private keys, 0644 for public keys).`,
		Example: `  # Restore a private key
  sshhades restore --input ~/backups/id_ed25519.enc --output ~/.ssh/id_ed25519
  
  # Restore with passphrase from environment
  sshhades restore -i id_rsa.enc -o ~/.ssh/id_rsa --passphrase-env SSH_PASSPHRASE
  
  # Force overwrite existing file
  sshhades restore -i id_ed25519.enc -o ~/.ssh/id_ed25519 --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRestore(flags)
		},
	}

	// Required flags
	cmd.Flags().StringVarP(&flags.input, "input", "i", "", "Path to encrypted SSH key file (required)")
	cmd.Flags().StringVarP(&flags.output, "output", "o", "", "Path for restored SSH key file (required)")
	
	// Optional flags
	cmd.Flags().StringVar(&flags.passphraseEnv, "passphrase-env", "", "Environment variable containing passphrase")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Overwrite existing output file")

	// Mark required flags
	cmd.MarkFlagRequired("input")
	cmd.MarkFlagRequired("output")

	return cmd
}

func runRestore(flags *restoreFlags) error {
	// Validate input file
	if err := storage.ValidatePath(flags.input); err != nil {
		return fmt.Errorf("invalid input path: %w", err)
	}

	if err := storage.ValidatePath(flags.output); err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Check if input file exists
	if !storage.FileExists(flags.input) {
		return fmt.Errorf("encrypted file not found: %s", flags.input)
	}

	// Check if output file already exists
	if storage.FileExists(flags.output) && !flags.force {
		return fmt.Errorf("output file already exists: %s (use --force to overwrite)", flags.output)
	}

	// Load encrypted file
	fmt.Printf("Loading encrypted file from %s...\n", flags.input)
	encFile, err := storage.LoadEncryptedFile(flags.input)
	if err != nil {
		return fmt.Errorf("failed to load encrypted file: %w", err)
	}

	// Validate encrypted file format
	if err := crypto.ValidateEncryptedFile(encFile); err != nil {
		return fmt.Errorf("invalid encrypted file format: %w", err)
	}

	// Read passphrase
	passphrase, err := readPassphrase(flags.passphraseEnv, "Enter passphrase for decryption: ")
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ClearBytes(passphrase)

	// Decrypt the key
	fmt.Println("Decrypting SSH key...")
	keyData, err := crypto.Decrypt(encFile, passphrase)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	defer crypto.ClearBytes(keyData)

	// Determine if this is a private key
	isPrivate := ssh.IsPrivateKey(keyData)

	// Write the restored key
	fmt.Printf("Restoring SSH key to %s...\n", flags.output)
	if err := ssh.WriteKeyFile(flags.output, keyData, isPrivate); err != nil {
		return fmt.Errorf("failed to write restored key: %w", err)
	}

	// Get absolute path for display
	absPath, _ := filepath.Abs(flags.output)
	fmt.Printf("✓ SSH key successfully decrypted and restored to: %s\n", absPath)
	
	if encFile.Header.Comment != "" {
		fmt.Printf("  Comment: %s\n", encFile.Header.Comment)
	}
	
	keyType := ssh.DetectKeyType(keyData)
	fmt.Printf("  Key type: %s\n", keyType)
	
	if isPrivate {
		fmt.Printf("  Permissions: 0600 (private key)\n")
	} else {
		fmt.Printf("  Permissions: 0644 (public key)\n")
	}
	
	fmt.Printf("  Encrypted: %s\n", encFile.Header.Timestamp.Format("2006-01-02 15:04:05 UTC"))

	return nil
}