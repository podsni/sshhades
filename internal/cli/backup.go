package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sshhades/sshhades/internal/crypto"
	"github.com/sshhades/sshhades/internal/github"
	"github.com/sshhades/sshhades/internal/ssh"
	"github.com/sshhades/sshhades/internal/storage"
	"github.com/sshhades/sshhades/pkg/format"
)

type backupFlags struct {
	input        string
	output       string
	comment      string
	algorithm    string
	iterations   uint32
	memory       uint32
	threads      uint8
	passphraseEnv string
	githubRepo   string
	githubToken  string
	fastMode     bool
}

func newBackupCommand() *cobra.Command {
	flags := &backupFlags{}

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Encrypt and backup an SSH key",
		Long: `Encrypt an SSH key using AES-256-GCM with Argon2id key derivation.
The encrypted key can optionally be uploaded to a private GitHub repository.`,
		Example: `  # Backup a private key
  sshhades backup --input ~/.ssh/id_ed25519 --output ~/backups/id_ed25519.enc --comment "Main SSH key"
  
	# Backup with custom security parameters
  sshhades backup -i ~/.ssh/id_rsa -o ~/backups/id_rsa.enc --iterations 200000 --memory 128
  
  # Backup with ChaCha20-Poly1305 algorithm
  sshhades backup -i ~/.ssh/id_ed25519 -o backup.enc --algorithm chacha20
  
  # Fast mode for development
  sshhades backup -i ~/.ssh/id_rsa -o backup.enc --fast
  
  # Backup and upload to GitHub
  sshhades backup -i ~/.ssh/id_ed25519 -o id_ed25519.enc --github-repo "user/ssh-backups"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBackup(flags)
		},
	}

	// Required flags
	cmd.Flags().StringVarP(&flags.input, "input", "i", "", "Path to SSH key file to backup (required)")
	cmd.Flags().StringVarP(&flags.output, "output", "o", "", "Path for encrypted output file")
	
	// Optional flags
	cmd.Flags().StringVarP(&flags.comment, "comment", "c", "", "Comment/label for the key")
	cmd.Flags().StringVarP(&flags.algorithm, "algorithm", "a", format.AlgorithmAESGCM, "Encryption algorithm (aes-gcm, chacha20)")
	cmd.Flags().Uint32VarP(&flags.iterations, "iterations", "n", 0, "Argon2id iterations (0 = auto based on mode)")
	cmd.Flags().Uint32Var(&flags.memory, "memory", 0, "Argon2id memory usage in MB (0 = auto)")
	cmd.Flags().Uint8Var(&flags.threads, "threads", 0, "Argon2id parallelism (0 = auto)")
	cmd.Flags().BoolVar(&flags.fastMode, "fast", false, "Use fast mode (development, less secure but faster)")
	cmd.Flags().StringVar(&flags.passphraseEnv, "passphrase-env", "", "Environment variable containing passphrase")
	cmd.Flags().StringVar(&flags.githubRepo, "github-repo", "", "GitHub repository for backup (owner/repo)")
	cmd.Flags().StringVar(&flags.githubToken, "github-token", "", "GitHub token (defaults to GITHUB_TOKEN env var)")

	// Mark required flags
	cmd.MarkFlagRequired("input")

	return cmd
}

func runBackup(flags *backupFlags) error {
	// Normalize algorithm name
	switch strings.ToLower(flags.algorithm) {
	case "aes", "aes-gcm", "aes-256-gcm":
		flags.algorithm = format.AlgorithmAESGCM
	case "chacha20", "chacha20-poly1305":
		flags.algorithm = format.AlgorithmChaCha20
	default:
		return fmt.Errorf("unsupported algorithm: %s (use: aes-gcm, chacha20)", flags.algorithm)
	}

	// Validate input file
	if err := storage.ValidatePath(flags.input); err != nil {
		return fmt.Errorf("invalid input path: %w", err)
	}

	// Read SSH key
	fmt.Printf("Reading SSH key from %s...\n", flags.input)
	keyData, err := ssh.ReadKeyFile(flags.input)
	if err != nil {
		return fmt.Errorf("failed to read SSH key: %w", err)
	}

	// Generate output path if not specified
	if flags.output == "" {
		flags.output = storage.CreateBackupPath(flags.input, "")
	}

	if err := storage.ValidatePath(flags.output); err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}

	// Check if output file already exists
	if storage.FileExists(flags.output) {
		return fmt.Errorf("output file already exists: %s", flags.output)
	}

	// Read passphrase
	passphrase, err := readPassphrase(flags.passphraseEnv, "Enter passphrase for encryption: ")
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ClearBytes(passphrase)

	// Set up encryption parameters
	var kdfParams crypto.KDFParams
	var header format.Header

	if flags.fastMode {
		kdfParams = crypto.FastKDFParams()
		header = format.FastHeader()
		fmt.Println("⚡ Using fast mode (development) - less secure but faster")
	} else {
		kdfParams = crypto.DefaultKDFParams()
		header = format.DefaultHeader()
	}

	// Override with custom parameters if provided
	if flags.iterations > 0 {
		kdfParams.Iterations = flags.iterations
		header.Iterations = flags.iterations
	}
	if flags.memory > 0 {
		kdfParams.Memory = flags.memory
		header.Memory = flags.memory
	}
	if flags.threads > 0 {
		kdfParams.Threads = flags.threads
		header.Threads = flags.threads
	}

	header.Algorithm = flags.algorithm
	header.Comment = flags.comment

	// Encrypt the key
	fmt.Printf("Encrypting SSH key with %s...\n", flags.algorithm)
	result, err := crypto.Encrypt(keyData, passphrase, flags.algorithm, kdfParams)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Create encrypted file structure
	encFile := &format.EncryptedFile{
		Header:     header,
		Salt:       result.Salt,
		Nonce:      result.Nonce,
		Ciphertext: result.Ciphertext,
		Tag:        result.Tag,
	}

	// Save encrypted file
	fmt.Printf("Saving encrypted key to %s...\n", flags.output)
	if err := storage.SaveEncryptedFile(flags.output, encFile); err != nil {
		return fmt.Errorf("failed to save encrypted file: %w", err)
	}

	// Upload to GitHub if requested
	if flags.githubRepo != "" {
		fmt.Printf("Uploading to GitHub repository %s...\n", flags.githubRepo)
		if err := uploadToGitHub(flags.output, flags.githubRepo, flags.githubToken, flags.comment); err != nil {
			fmt.Printf("⚠️  Warning: GitHub upload failed: %v\n", err)
			fmt.Println("   The file has been saved locally successfully.")
		} else {
			fmt.Println("✓ Successfully uploaded to GitHub")
		}
	}

	// Get absolute path for display
	absPath, _ := filepath.Abs(flags.output)
	fmt.Printf("✓ SSH key successfully encrypted and saved to: %s\n", absPath)
	
	if flags.comment != "" {
		fmt.Printf("  Comment: %s\n", flags.comment)
	}
	fmt.Printf("  Encryption: %s with Argon2id (%d iterations)\n", flags.algorithm, header.Iterations)

	return nil
}

// uploadToGitHub handles uploading the encrypted file to GitHub repository
func uploadToGitHub(localPath, repository, token, comment string) error {
	// Create GitHub client
	client, err := github.NewClient(token, repository)
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Ensure repository structure exists
	if err := client.EnsureRepository(ctx); err != nil {
		return fmt.Errorf("failed to setup repository: %w", err)
	}

	// Create/update .gitignore for safety
	if err := client.CreateGitignore(ctx); err != nil {
		return fmt.Errorf("failed to setup .gitignore: %w", err)
	}

	// Generate remote path and commit message
	remotePath := github.GenerateRemotePath(localPath)
	commitMessage := github.GenerateCommitMessage(filepath.Base(localPath), comment)

	// Upload the file
	if err := client.UploadFile(ctx, localPath, remotePath, commitMessage); err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	return nil
}