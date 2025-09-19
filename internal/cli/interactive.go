package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sshhades/sshhades/internal/ssh"
	"github.com/sshhades/sshhades/pkg/format"
)

// InteractiveKeySelector provides interactive SSH key selection
type InteractiveKeySelector struct {
	sshDir string
	keys   []ssh.KeyInfo
}

// NewInteractiveKeySelector creates a new interactive key selector
func NewInteractiveKeySelector() (*InteractiveKeySelector, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	
	sshDir := filepath.Join(homeDir, ".ssh")
	
	return &InteractiveKeySelector{
		sshDir: sshDir,
	}, nil
}

// SelectKey shows interactive menu for key selection
func (iks *InteractiveKeySelector) SelectKey() (string, error) {
	// Find SSH keys
	keys, err := ssh.FindSSHKeys(iks.sshDir)
	if err != nil {
		return "", fmt.Errorf("failed to find SSH keys: %w", err)
	}
	
	if len(keys) == 0 {
		fmt.Printf("❌ Tidak ditemukan SSH key di %s\n", iks.sshDir)
		fmt.Println("💡 Tip: Buat SSH key terlebih dahulu dengan: ssh-keygen -t ed25519")
		return "", fmt.Errorf("no SSH keys found")
	}
	
	iks.keys = keys
	
	// Show available keys
	fmt.Printf("🔑 SSH Keys yang ditemukan di %s:\n\n", iks.sshDir)
	
	for i, key := range keys {
		status := "📄 public"
		if key.HasPrivate {
			status = "🔐 private"
		}
		
		relPath, _ := filepath.Rel(iks.sshDir, key.Path)
		fmt.Printf("  [%d] %-20s  %s (%s, %d bytes)\n", 
			i+1, relPath, key.Type, status, key.Size)
	}
	
	fmt.Printf("\n📝 Pilih key yang ingin di-backup (1-%d): ", len(keys))
	
	// Read user input
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	
	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil {
		return "", fmt.Errorf("pilihan tidak valid: %s", input)
	}
	
	if choice < 1 || choice > len(keys) {
		return "", fmt.Errorf("pilihan harus antara 1-%d", len(keys))
	}
	
	selectedKey := keys[choice-1]
	fmt.Printf("✅ Dipilih: %s\n", selectedKey.Path)
	
	return selectedKey.Path, nil
}

// SelectAlgorithm shows interactive menu for algorithm selection
func SelectAlgorithm() (string, error) {
	algorithms := []struct {
		name        string
		description string
	}{
		{format.AlgorithmAESGCM, "AES-256-GCM (Standar, cepat, banyak didukung)"},
		{format.AlgorithmChaCha20, "ChaCha20-Poly1305 (Modern, aman, mobile-friendly)"},
	}
	
	fmt.Println("🔒 Pilih algoritma enkripsi:")
	fmt.Println()
	
	for i, alg := range algorithms {
		fmt.Printf("  [%d] %s\n      %s\n\n", i+1, alg.name, alg.description)
	}
	
	fmt.Printf("📝 Pilih algoritma (1-%d) [default: 1]: ", len(algorithms))
	
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	
	input = strings.TrimSpace(input)
	if input == "" {
		input = "1" // Default to AES-GCM
	}
	
	choice, err := strconv.Atoi(input)
	if err != nil {
		return "", fmt.Errorf("pilihan tidak valid: %s", input)
	}
	
	if choice < 1 || choice > len(algorithms) {
		return "", fmt.Errorf("pilihan harus antara 1-%d", len(algorithms))
	}
	
	selected := algorithms[choice-1]
	fmt.Printf("✅ Dipilih: %s\n", selected.name)
	
	return selected.name, nil
}

// SelectPerformanceMode shows interactive menu for performance mode
func SelectPerformanceMode() (bool, error) {
	modes := []struct {
		name        string
		description string
		fast        bool
	}{
		{"Production", "Keamanan maksimal (lambat, 100k iterasi)", false},
		{"Development", "Keamanan good (cepat, 1k iterasi)", true},
	}
	
	fmt.Println("⚡ Pilih mode performa:")
	fmt.Println()
	
	for i, mode := range modes {
		fmt.Printf("  [%d] %s\n      %s\n\n", i+1, mode.name, mode.description)
	}
	
	fmt.Printf("📝 Pilih mode (1-%d) [default: 2 untuk development]: ", len(modes))
	
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}
	
	input = strings.TrimSpace(input)
	if input == "" {
		input = "2" // Default to development mode
	}
	
	choice, err := strconv.Atoi(input)
	if err != nil {
		return false, fmt.Errorf("pilihan tidak valid: %s", input)
	}
	
	if choice < 1 || choice > len(modes) {
		return false, fmt.Errorf("pilihan harus antara 1-%d", len(modes))
	}
	
	selected := modes[choice-1]
	fmt.Printf("✅ Dipilih: %s\n", selected.name)
	
	return selected.fast, nil
}