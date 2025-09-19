package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// GitHubConfig holds GitHub authentication configuration
type GitHubConfig struct {
	Token      string `json:"token,omitempty"`
	Username   string `json:"username"`
	AuthMethod string `json:"auth_method"` // "token" or "ssh"
	SSHKeyPath string `json:"ssh_key_path,omitempty"`
	RepoName   string `json:"repo_name"`
	RepoOwner  string `json:"repo_owner"`
}

// Config holds application configuration
type Config struct {
	GitHub *GitHubConfig `json:"github,omitempty"`
}

func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	
	configDir := filepath.Join(homeDir, ".config", "sshhades")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}
	
	return configDir, nil
}

func getConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.json"), nil
}

// LoadConfig loads configuration from file
func LoadConfig() (*Config, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}
	
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Return empty config if file doesn't exist
		return &Config{}, nil
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	return &config, nil
}

// SaveConfig saves configuration to file
func (c *Config) SaveConfig() error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}
	
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// SetGitHubConfig sets GitHub configuration
func (c *Config) SetGitHubConfig(github *GitHubConfig) {
	c.GitHub = github
}

// GetGitHubConfig gets GitHub configuration
func (c *Config) GetGitHubConfig() *GitHubConfig {
	return c.GitHub
}

// IsGitHubConfigured checks if GitHub is configured
func (c *Config) IsGitHubConfigured() bool {
	if c.GitHub == nil {
		return false
	}
	
	switch c.GitHub.AuthMethod {
	case "token":
		return c.GitHub.Token != "" && c.GitHub.Username != ""
	case "ssh":
		return c.GitHub.SSHKeyPath != "" && c.GitHub.Username != ""
	default:
		return false
	}
}