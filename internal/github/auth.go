package github

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/google/go-github/v57/github"
	"github.com/sshhades/sshhades/internal/config"
	"golang.org/x/oauth2"
)

var (
	// Styles for beautiful CLI
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7C3AED")).
		MarginBottom(1)

	successStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#10B981")).
		Bold(true)

	errorStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#EF4444")).
		Bold(true)

	infoStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#3B82F6"))

	promptStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F59E0B")).
		Bold(true)
)

// AuthenticatedClient holds GitHub client and config
type AuthenticatedClient struct {
	Client *github.Client
	Config *config.GitHubConfig
}

// NewAuthenticatedClient creates a new authenticated GitHub client
func NewAuthenticatedClient(cfg *config.GitHubConfig) (*AuthenticatedClient, error) {
	var client *github.Client

	switch cfg.AuthMethod {
	case "token":
		if cfg.Token == "" {
			return nil, fmt.Errorf("GitHub token is required")
		}
		
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: cfg.Token},
		)
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)

	case "ssh":
		// For SSH, we use the default client but SSH operations will be handled separately
		client = github.NewClient(nil)

	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", cfg.AuthMethod)
	}

	return &AuthenticatedClient{
		Client: client,
		Config: cfg,
	}, nil
}

// ValidateToken validates GitHub token
func ValidateToken(token string) (*github.User, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub token: %w", err)
	}

	return user, nil
}

// FindSSHKeys finds available SSH keys for GitHub
func FindSSHKeys() ([]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read .ssh directory: %w", err)
	}

	var sshKeys []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Look for private keys (no .pub extension)
		if !strings.HasSuffix(name, ".pub") && 
		   !strings.HasSuffix(name, ".ppk") &&
		   name != "known_hosts" &&
		   name != "config" &&
		   name != "authorized_keys" {
			
			// Check if corresponding public key exists
			pubKeyPath := filepath.Join(sshDir, name+".pub")
			if _, err := os.Stat(pubKeyPath); err == nil {
				sshKeys = append(sshKeys, filepath.Join(sshDir, name))
			}
		}
	}

	return sshKeys, nil
}

// TestSSHConnection tests SSH connection to GitHub
func TestSSHConnection(sshKeyPath string) error {
	cmd := exec.Command("ssh", "-T", "-i", sshKeyPath, "-o", "StrictHostKeyChecking=no", "git@github.com")
	output, _ := cmd.CombinedOutput()
	
	// GitHub SSH test returns exit code 1 but with success message
	outputStr := string(output)
	if strings.Contains(outputStr, "successfully authenticated") {
		return nil
	}

	return fmt.Errorf("SSH connection failed: %s", outputStr)
}

// GetGitHubUsername extracts username from SSH test output or API
func GetGitHubUsername(authMethod, token, sshKeyPath string) (string, error) {
	switch authMethod {
	case "token":
		user, err := ValidateToken(token)
		if err != nil {
			return "", err
		}
		return user.GetLogin(), nil

	case "ssh":
		cmd := exec.Command("ssh", "-T", "-i", sshKeyPath, "-o", "StrictHostKeyChecking=no", "git@github.com")
		output, _ := cmd.CombinedOutput()
		outputStr := string(output)

		// Parse username from SSH output: "Hi username! You've successfully authenticated..."
		if strings.Contains(outputStr, "successfully authenticated") {
			parts := strings.Split(outputStr, " ")
			if len(parts) > 1 {
				username := strings.TrimSuffix(parts[1], "!")
				return username, nil
			}
		}

		return "", fmt.Errorf("failed to get username from SSH: %s", outputStr)

	default:
		return "", fmt.Errorf("unsupported authentication method: %s", authMethod)
	}
}

// CreateRepository creates a new GitHub repository
func (ac *AuthenticatedClient) CreateRepository(ctx context.Context, name, description string, private bool) (*github.Repository, error) {
	repo := &github.Repository{
		Name:        github.String(name),
		Description: github.String(description),
		Private:     github.Bool(private),
		AutoInit:    github.Bool(true),
	}

	createdRepo, _, err := ac.Client.Repositories.Create(ctx, "", repo)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	return createdRepo, nil
}

// ListRepositories lists user's repositories
func (ac *AuthenticatedClient) ListRepositories(ctx context.Context) ([]*github.Repository, error) {
	opt := &github.RepositoryListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	var allRepos []*github.Repository
	for {
		repos, resp, err := ac.Client.Repositories.List(ctx, "", opt)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allRepos, nil
}

// GetRepository gets a specific repository
func (ac *AuthenticatedClient) GetRepository(ctx context.Context, owner, name string) (*github.Repository, error) {
	repo, _, err := ac.Client.Repositories.Get(ctx, owner, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}

	return repo, nil
}

// UploadFile uploads a file to GitHub repository
func (ac *AuthenticatedClient) UploadFile(ctx context.Context, owner, repo, path string, content []byte, message string) error {
	opts := &github.RepositoryContentFileOptions{
		Message: github.String(message),
		Content: content,
	}

	_, _, err := ac.Client.Repositories.CreateFile(ctx, owner, repo, path, opts)
	if err != nil {
		// If file exists, try to update it
		if strings.Contains(err.Error(), "already exists") {
			// Get the existing file to get its SHA
			existingFile, _, _, err := ac.Client.Repositories.GetContents(ctx, owner, repo, path, nil)
			if err != nil {
				return fmt.Errorf("failed to get existing file: %w", err)
			}

			opts.SHA = existingFile.SHA
			_, _, err = ac.Client.Repositories.UpdateFile(ctx, owner, repo, path, opts)
			if err != nil {
				return fmt.Errorf("failed to update file: %w", err)
			}
		} else {
			return fmt.Errorf("failed to create file: %w", err)
		}
	}

	return nil
}

// PrettyPrint utilities for better CLI experience
func PrintTitle(text string) {
	fmt.Println(titleStyle.Render("🔐 " + text))
}

func PrintSuccess(text string) {
	fmt.Println(successStyle.Render("✅ " + text))
}

func PrintError(text string) {
	fmt.Println(errorStyle.Render("❌ " + text))
}

func PrintInfo(text string) {
	fmt.Println(infoStyle.Render("ℹ️  " + text))
}

func PrintPrompt(text string) {
	fmt.Print(promptStyle.Render("❓ " + text + ": "))
}