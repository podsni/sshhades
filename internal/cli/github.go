package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/sshhades/sshhades/internal/config"
	"github.com/sshhades/sshhades/internal/github"
	"golang.org/x/term"
)

func NewGitHubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "github",
		Short: "Manage GitHub integration",
		Long:  `Configure GitHub authentication and repository settings for automated backups.`,
		RunE:  runGitHubSetup,
	}

	cmd.AddCommand(NewGitHubLoginCmd())
	cmd.AddCommand(NewGitHubStatusCmd())
	cmd.AddCommand(NewGitHubLogoutCmd())
	cmd.AddCommand(NewGitHubReposCmd())

	return cmd
}

func NewGitHubLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Setup GitHub authentication",
		Long:  `Interactive wizard to setup GitHub authentication using token or SSH key.`,
		RunE:  runGitHubLogin,
	}
}

func NewGitHubStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show GitHub integration status",
		Long:  `Display current GitHub authentication status and configuration.`,
		RunE:  runGitHubStatus,
	}
}

func NewGitHubLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove GitHub authentication",
		Long:  `Remove stored GitHub credentials and configuration.`,
		RunE:  runGitHubLogout,
	}
}

func NewGitHubReposCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repos",
		Short: "Manage GitHub repositories",
		Long:  `List, create, and manage GitHub repositories for SSH key backups.`,
		RunE:  runGitHubRepos,
	}
}

func runGitHubSetup(cmd *cobra.Command, args []string) error {
	return runGitHubLogin(cmd, args)
}

func runGitHubLogin(cmd *cobra.Command, args []string) error {
	github.PrintTitle("GitHub Integration Setup")
	
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.IsGitHubConfigured() {
		github.PrintInfo("GitHub is already configured!")
		fmt.Printf("Current setup: %s authentication as %s\n", 
			cfg.GitHub.AuthMethod, cfg.GitHub.Username)
		
		fmt.Print("Do you want to reconfigure? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		
		if response != "y" && response != "yes" {
			github.PrintInfo("GitHub configuration unchanged.")
			return nil
		}
	}

	// Choose authentication method
	github.PrintPrompt("Choose GitHub authentication method")
	fmt.Println("\n1. Personal Access Token (recommended)")
	fmt.Println("2. SSH Key")
	fmt.Print("\nEnter your choice (1 or 2): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var githubConfig *config.GitHubConfig

	switch choice {
	case "1":
		githubConfig, err = setupTokenAuth()
	case "2":
		githubConfig, err = setupSSHAuth()
	default:
		return fmt.Errorf("invalid choice. Please enter 1 or 2")
	}

	if err != nil {
		github.PrintError(fmt.Sprintf("Setup failed: %v", err))
		return err
	}

	// Setup repository
	repoName, err := setupRepository(githubConfig)
	if err != nil {
		github.PrintError(fmt.Sprintf("Repository setup failed: %v", err))
		return err
	}

	githubConfig.RepoName = repoName
	githubConfig.RepoOwner = githubConfig.Username

	// Save configuration
	cfg.SetGitHubConfig(githubConfig)
	if err := cfg.SaveConfig(); err != nil {
		github.PrintError(fmt.Sprintf("Failed to save configuration: %v", err))
		return err
	}

	github.PrintSuccess("GitHub integration configured successfully!")
	github.PrintInfo(fmt.Sprintf("Repository: %s/%s", githubConfig.Username, githubConfig.RepoName))
	github.PrintInfo("You can now use 'sshhades backup --github' to backup to GitHub")

	return nil
}

func setupTokenAuth() (*config.GitHubConfig, error) {
	github.PrintInfo("Setting up Personal Access Token authentication...")
	github.PrintInfo("You need a GitHub Personal Access Token with 'repo' scope.")
	github.PrintInfo("Create one at: https://github.com/settings/tokens")
	
	fmt.Print("\nEnter your GitHub Personal Access Token: ")
	
	// Hide token input
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %w", err)
	}
	
	token := string(bytePassword)
	fmt.Println() // New line after hidden input
	
	if token == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}

	github.PrintInfo("Validating token...")
	user, err := github.ValidateToken(token)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	github.PrintSuccess(fmt.Sprintf("Token validated! Logged in as: %s", user.GetLogin()))

	return &config.GitHubConfig{
		Token:      token,
		Username:   user.GetLogin(),
		AuthMethod: "token",
	}, nil
}

func setupSSHAuth() (*config.GitHubConfig, error) {
	github.PrintInfo("Setting up SSH Key authentication...")
	
	// Find available SSH keys
	sshKeys, err := github.FindSSHKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to find SSH keys: %w", err)
	}

	if len(sshKeys) == 0 {
		return nil, fmt.Errorf("no SSH keys found in ~/.ssh/. Please generate an SSH key first")
	}

	// Let user choose SSH key
	fmt.Println("\nAvailable SSH keys:")
	for i, key := range sshKeys {
		fmt.Printf("%d. %s\n", i+1, key)
	}

	fmt.Printf("\nSelect SSH key (1-%d): ", len(sshKeys))
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	keyIndex, err := strconv.Atoi(choice)
	if err != nil || keyIndex < 1 || keyIndex > len(sshKeys) {
		return nil, fmt.Errorf("invalid choice. Please enter a number between 1 and %d", len(sshKeys))
	}

	selectedKey := sshKeys[keyIndex-1]

	github.PrintInfo(fmt.Sprintf("Testing SSH connection with key: %s", selectedKey))
	
	// Test SSH connection
	if err := github.TestSSHConnection(selectedKey); err != nil {
		github.PrintError("SSH connection test failed!")
		github.PrintInfo("Make sure your SSH key is added to your GitHub account:")
		github.PrintInfo("https://github.com/settings/ssh/new")
		return nil, err
	}

	// Get username from SSH
	username, err := github.GetGitHubUsername("ssh", "", selectedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get GitHub username: %w", err)
	}

	github.PrintSuccess(fmt.Sprintf("SSH authentication successful! Logged in as: %s", username))

	return &config.GitHubConfig{
		Username:   username,
		AuthMethod: "ssh",
		SSHKeyPath: selectedKey,
	}, nil
}

func setupRepository(githubConfig *config.GitHubConfig) (string, error) {
	github.PrintInfo("Setting up backup repository...")

	// Create authenticated client
	client, err := github.NewAuthenticatedClient(githubConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create GitHub client: %w", err)
	}

	ctx := context.Background()

	// List existing repositories
	if githubConfig.AuthMethod == "token" {
		repos, err := client.ListRepositories(ctx)
		if err != nil {
			github.PrintError("Failed to list repositories, but continuing...")
		} else {
			fmt.Println("\nYour existing repositories:")
			for i, repo := range repos {
				if i >= 10 { // Limit display
					fmt.Printf("... and %d more\n", len(repos)-10)
					break
				}
				privacy := "public"
				if repo.GetPrivate() {
					privacy = "private"
				}
				fmt.Printf("  - %s (%s)\n", repo.GetName(), privacy)
			}
		}
	}

	fmt.Print("\nEnter repository name for backups (default: ssh-keys-backup): ")
	reader := bufio.NewReader(os.Stdin)
	repoName, _ := reader.ReadString('\n')
	repoName = strings.TrimSpace(repoName)

	if repoName == "" {
		repoName = "ssh-keys-backup"
	}

	// Check if repository exists (only for token auth)
	if githubConfig.AuthMethod == "token" {
		_, err := client.GetRepository(ctx, githubConfig.Username, repoName)
		if err == nil {
			github.PrintInfo(fmt.Sprintf("Repository '%s' already exists. Using existing repository.", repoName))
			return repoName, nil
		}

		// Ask if user wants to create the repository
		fmt.Print("Repository doesn't exist. Create it? (Y/n): ")
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))

		if response == "" || response == "y" || response == "yes" {
			github.PrintInfo("Creating repository...")
			_, err := client.CreateRepository(ctx, repoName, "SSH Keys Backup Repository", true)
			if err != nil {
				return "", fmt.Errorf("failed to create repository: %w", err)
			}
			github.PrintSuccess(fmt.Sprintf("Repository '%s' created successfully!", repoName))
		}
	}

	return repoName, nil
}

func runGitHubStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	github.PrintTitle("GitHub Integration Status")

	if !cfg.IsGitHubConfigured() {
		github.PrintError("GitHub is not configured")
		github.PrintInfo("Run 'sshhades github login' to setup GitHub integration")
		return nil
	}

	githubCfg := cfg.GetGitHubConfig()
	
	github.PrintSuccess("GitHub is configured")
	fmt.Printf("  Username: %s\n", githubCfg.Username)
	fmt.Printf("  Authentication: %s\n", githubCfg.AuthMethod)
	
	if githubCfg.AuthMethod == "ssh" {
		fmt.Printf("  SSH Key: %s\n", githubCfg.SSHKeyPath)
	}
	
	if githubCfg.RepoName != "" {
		fmt.Printf("  Repository: %s/%s\n", githubCfg.RepoOwner, githubCfg.RepoName)
	}

	return nil
}

func runGitHubLogout(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if !cfg.IsGitHubConfigured() {
		github.PrintInfo("GitHub is not configured")
		return nil
	}

	fmt.Print("Are you sure you want to remove GitHub configuration? (y/N): ")
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response != "y" && response != "yes" {
		github.PrintInfo("GitHub configuration unchanged")
		return nil
	}

	cfg.SetGitHubConfig(nil)
	if err := cfg.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	github.PrintSuccess("GitHub configuration removed")
	return nil
}

func runGitHubRepos(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if !cfg.IsGitHubConfigured() {
		github.PrintError("GitHub is not configured")
		github.PrintInfo("Run 'sshhades github login' to setup GitHub integration")
		return nil
	}

	githubCfg := cfg.GetGitHubConfig()
	
	if githubCfg.AuthMethod != "token" {
		github.PrintError("Repository management requires token authentication")
		github.PrintInfo("SSH authentication doesn't support repository listing via API")
		return nil
	}

	client, err := github.NewAuthenticatedClient(githubCfg)
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	github.PrintTitle("Your GitHub Repositories")

	ctx := context.Background()
	repos, err := client.ListRepositories(ctx)
	if err != nil {
		return fmt.Errorf("failed to list repositories: %w", err)
	}

	if len(repos) == 0 {
		github.PrintInfo("No repositories found")
		return nil
	}

	for _, repo := range repos {
		privacy := "public"
		if repo.GetPrivate() {
			privacy = "private"
		}
		
		icon := "📖"
		if repo.GetPrivate() {
			icon = "🔒"
		}
		
		fmt.Printf("%s %s (%s)\n", icon, repo.GetName(), privacy)
		if repo.GetDescription() != "" {
			fmt.Printf("   %s\n", repo.GetDescription())
		}
	}

	return nil
}