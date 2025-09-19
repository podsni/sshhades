package cli

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// NewRootCommand creates the root CLI command
func NewRootCommand(version, buildTime, gitCommit string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "sshhades",
		Short: "SSH key encryption and backup tool",
		Long: `SSH Hades is a secure tool for encrypting and backing up SSH keys.
It uses AES-256-GCM encryption with Argon2id key derivation to protect your SSH keys.`,
		Version: fmt.Sprintf("%s (built: %s, commit: %s)", version, buildTime, gitCommit),
	}

	// Add subcommands
	rootCmd.AddCommand(NewBackupCmd())
	rootCmd.AddCommand(NewRestoreCmd())
	rootCmd.AddCommand(NewListCmd())
	rootCmd.AddCommand(NewVerifyCmd())
	rootCmd.AddCommand(NewInteractiveCmd())
	rootCmd.AddCommand(NewGitHubCmd())

	return rootCmd

	return rootCmd
}

// readPassphrase reads a passphrase from the user or environment
func readPassphrase(envVar string, prompt string) ([]byte, error) {
	// Try environment variable first
	if envVar != "" {
		if passphrase := os.Getenv(envVar); passphrase != "" {
			return []byte(passphrase), nil
		}
	}

	// Prompt user interactively
	fmt.Fprint(os.Stderr, prompt)
	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr) // New line after password input
	
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}

	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	return passphrase, nil
}