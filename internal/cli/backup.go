package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sshhades/sshhades/internal/config"
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
	githubUpload bool
}

func NewBackupCmd() *cobra.Command {
	var (
		inputFile   string
		outputFile  string
		comment     string
		algorithm   string
		fast        bool
		githubUpload bool
	)

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Encrypt and backup SSH key",
		Long: `Encrypt an SSH private key using AES-256-GCM or ChaCha20-Poly1305 encryption.
		
The encrypted file can be safely stored or shared, and can optionally be uploaded to GitHub.`,
		Example: `  # Basic backup with AES-256-GCM
  sshhades backup --input ~/.ssh/id_ed25519 --output backup.enc

  # Fast backup with ChaCha20-Poly1305
  sshhades backup -i ~/.ssh/id_rsa -o backup.enc --algorithm chacha20 --fast

  # Backup with GitHub upload
  sshhades backup -i ~/.ssh/id_ed25519 -o backup.enc --github

  # Interactive backup with comment
  sshhades backup -i ~/.ssh/id_ed25519 -o backup.enc --comment "My development key"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := &backupFlags{
				input:        inputFile,
				output:       outputFile,
				comment:      comment,
				algorithm:    algorithm,
				fastMode:     fast,
				githubUpload: githubUpload,
			}
			return runBackup(flags)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input SSH private key file (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output encrypted file (required)")
	cmd.Flags().StringVarP(&comment, "comment", "c", "", "Comment/description for the backup")
	cmd.Flags().StringVarP(&algorithm, "algorithm", "a", "aes", "Encryption algorithm: aes (AES-256-GCM) or chacha20 (ChaCha20-Poly1305)")
	cmd.Flags().BoolVarP(&fast, "fast", "f", false, "Use fast mode (less secure but faster)")
	cmd.Flags().BoolVar(&githubUpload, "github", false, "Upload encrypted backup to GitHub")

	cmd.MarkFlagRequired("input")
	cmd.MarkFlagRequired("output")

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
		if err := uploadToGitHub(flags.output, flags.comment); err != nil {
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

	// Upload to GitHub if requested
	if flags.githubUpload {
		fmt.Println("\n📤 Uploading to GitHub...")
		if err := uploadToGitHub(flags.output, flags.comment); err != nil {
			github.PrintError(fmt.Sprintf("GitHub upload failed: %v", err))
			github.PrintInfo("Backup saved locally, but not uploaded to GitHub")
		} else {
			github.PrintSuccess("Successfully uploaded to GitHub!")
		}
	}

	return nil
}

// uploadToGitHub handles uploading the encrypted file to GitHub repository
func uploadToGitHub(localPath, comment string) error {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if !cfg.IsGitHubConfigured() {
		return fmt.Errorf("GitHub is not configured. Run 'sshhades github login' first")
	}

	githubCfg := cfg.GetGitHubConfig()

	// Create authenticated client
	client, err := github.NewAuthenticatedClient(githubCfg)
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	// Read the encrypted file
	content, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Generate remote path and commit message
	filename := filepath.Base(localPath)
	remotePath := fmt.Sprintf("ssh-keys/%s", filename)
	
	commitMessage := fmt.Sprintf("Backup SSH key: %s", filename)
	if comment != "" {
		commitMessage = fmt.Sprintf("Backup SSH key: %s - %s", filename, comment)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upload file
	return client.UploadFile(ctx, githubCfg.RepoOwner, githubCfg.RepoName, remotePath, content, commitMessage)
}