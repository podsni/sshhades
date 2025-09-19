package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sshhades/sshhades/internal/crypto"
	"github.com/sshhades/sshhades/internal/ssh"
	"github.com/sshhades/sshhades/internal/storage"
)

type listFlags struct {
	directory string
	verbose   bool
}

func newListCommand() *cobra.Command {
	flags := &listFlags{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available SSH keys and encrypted backups",
		Long: `List SSH keys in the ~/.ssh directory and encrypted backup files.
Shows key types, file sizes, and encryption status.`,
		Example: `  # List keys in default ~/.ssh directory
  sshhades list
  
  # List keys in specific directory
  sshhades list --directory ~/backups
  
  # Show detailed information
  sshhades list --verbose`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(flags)
		},
	}

	cmd.Flags().StringVarP(&flags.directory, "directory", "d", "", "Directory to search (defaults to ~/.ssh)")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Show detailed information")

	return cmd
}

func runList(flags *listFlags) error {
	var searchDir string
	
	if flags.directory != "" {
		searchDir = flags.directory
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		searchDir = filepath.Join(homeDir, ".ssh")
	}

	// Check if directory exists
	if _, err := os.Stat(searchDir); os.IsNotExist(err) {
		fmt.Printf("Directory not found: %s\n", searchDir)
		return nil
	}

	fmt.Printf("Searching for SSH keys in: %s\n\n", searchDir)

	// Find SSH keys
	keys, err := ssh.FindSSHKeys(searchDir)
	if err != nil {
		return fmt.Errorf("failed to search for SSH keys: %w", err)
	}

	if len(keys) == 0 {
		fmt.Println("No SSH keys found.")
		return nil
	}

	// Also look for encrypted files
	encryptedFiles, err := findEncryptedFiles(searchDir)
	if err != nil {
		fmt.Printf("Warning: failed to search for encrypted files: %v\n", err)
	}

	// Display SSH keys
	fmt.Printf("SSH Keys Found (%d):\n", len(keys))
	fmt.Println(strings.Repeat("-", 50))

	for _, key := range keys {
		relPath, _ := filepath.Rel(searchDir, key.Path)
		
		status := ""
		if key.HasPrivate {
			status = "private"
		} else {
			status = "public"
		}

		fmt.Printf("  %-20s  %s (%s)\n", relPath, key.Type, status)
		
		if flags.verbose {
			fmt.Printf("    Path: %s\n", key.Path)
			fmt.Printf("    Size: %d bytes\n", key.Size)
			fmt.Println()
		}
	}

	// Display encrypted files
	if len(encryptedFiles) > 0 {
		fmt.Printf("\nEncrypted Backups Found (%d):\n", len(encryptedFiles))
		fmt.Println(strings.Repeat("-", 50))

		for _, encFile := range encryptedFiles {
			relPath, _ := filepath.Rel(searchDir, encFile.Path)
			fmt.Printf("  %-20s  encrypted backup\n", relPath)
			
			if flags.verbose {
				fmt.Printf("    Path: %s\n", encFile.Path)
				fmt.Printf("    Size: %d bytes\n", encFile.Size)
				if encFile.Comment != "" {
					fmt.Printf("    Comment: %s\n", encFile.Comment)
				}
				fmt.Printf("    Created: %s\n", encFile.Timestamp.Format("2006-01-02 15:04:05"))
				fmt.Println()
			}
		}
	}

	return nil
}

type encryptedFileInfo struct {
	Path      string
	Size      int64
	Comment   string
	Timestamp time.Time
}

func findEncryptedFiles(dir string) ([]encryptedFileInfo, error) {
	var encFiles []encryptedFileInfo

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".enc") {
			continue
		}

		path := filepath.Join(dir, name)
		
		// Try to load and parse the encrypted file
		encFile, err := storage.LoadEncryptedFile(path)
		if err != nil {
			continue // Skip files that aren't valid encrypted files
		}

		// Validate it's one of our encrypted files
		if err := crypto.ValidateEncryptedFile(encFile); err != nil {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		encInfo := encryptedFileInfo{
			Path:      path,
			Size:      info.Size(),
			Comment:   encFile.Header.Comment,
			Timestamp: encFile.Header.Timestamp,
		}

		encFiles = append(encFiles, encInfo)
	}

	return encFiles, nil
}