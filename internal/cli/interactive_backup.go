package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sshhades/sshhades/internal/config"
	"github.com/sshhades/sshhades/internal/crypto"
	"github.com/sshhades/sshhades/internal/github"
	"github.com/sshhades/sshhades/internal/ssh"
	"github.com/sshhades/sshhades/internal/storage"
	"github.com/sshhades/sshhades/pkg/format"
)

func NewInteractiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "interactive",
		Short: "Mode interaktif untuk backup SSH key",
		Long: `Mode interaktif yang memudahkan backup SSH key dengan:
- Pilihan file SSH dari ~/.ssh secara interaktif
- Pilihan algoritma enkripsi (AES-256-GCM atau ChaCha20-Poly1305)
- Pilihan mode performa (Production vs Development)
- UI yang user-friendly dengan suggestions`,
		Aliases: []string{"i", "wizard"},
		Example: `  # Jalankan mode interaktif
  sshhades interactive
  
  # Atau gunakan alias
  sshhades i
  sshhades wizard`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractive()
		},
	}

	return cmd
}

func runInteractive() error {
	fmt.Println("🎯 SSH Hades - Mode Interaktif")
	fmt.Println("=" + strings.Repeat("=", 40))
	fmt.Println()

	// Step 1: Select SSH key
	fmt.Println("📁 Step 1: Pilih SSH Key")
	selector, err := NewInteractiveKeySelector()
	if err != nil {
		return fmt.Errorf("failed to create key selector: %w", err)
	}

	inputPath, err := selector.SelectKey()
	if err != nil {
		return fmt.Errorf("failed to select key: %w", err)
	}
	fmt.Println()

	// Step 2: Select algorithm
	fmt.Println("🔒 Step 2: Pilih Algoritma Enkripsi")
	algorithm, err := SelectAlgorithm()
	if err != nil {
		return fmt.Errorf("failed to select algorithm: %w", err)
	}
	fmt.Println()

	// Step 3: Select performance mode
	fmt.Println("⚡ Step 3: Pilih Mode Performa")
	fastMode, err := SelectPerformanceMode()
	if err != nil {
		return fmt.Errorf("failed to select performance mode: %w", err)
	}
	fmt.Println()

	// Step 4: Get comment
	fmt.Println("💬 Step 4: Komentar (opsional)")
	fmt.Print("📝 Masukkan komentar untuk backup ini: ")
	comment := ""
	fmt.Scanln(&comment)
	if comment == "" {
		comment = fmt.Sprintf("Interactive backup - %s", filepath.Base(inputPath))
	}
	fmt.Printf("✅ Komentar: %s\n", comment)
	fmt.Println()

	// Step 5: Generate output path
	outputPath := storage.CreateBackupPath(inputPath, "")
	fmt.Printf("💾 Step 5: Output file akan disimpan di: %s\n", outputPath)
	fmt.Println()

	// Check if output file already exists
	if storage.FileExists(outputPath) {
		fmt.Printf("⚠️  File output sudah ada: %s\n", outputPath)
		fmt.Print("❓ Overwrite? (y/N): ")
		var overwrite string
		fmt.Scanln(&overwrite)
		if overwrite != "y" && overwrite != "Y" {
			fmt.Println("❌ Backup dibatalkan")
			return nil
		}
	}

	// Step 6: Get passphrase
	fmt.Println("🔐 Step 6: Passphrase")
	passphrase, err := readPassphrase("", "🔑 Masukkan passphrase untuk enkripsi: ")
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}
	defer crypto.ClearBytes(passphrase)

	// Step 7: Perform backup
	fmt.Println()
	fmt.Println("🚀 Step 7: Memulai Backup...")
	fmt.Printf("📖 Membaca SSH key dari %s...\n", inputPath)

	// Read SSH key
	keyData, err := ssh.ReadKeyFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH key: %w", err)
	}

	// Set up encryption parameters
	var kdfParams crypto.KDFParams
	var header format.Header

	if fastMode {
		kdfParams = crypto.FastKDFParams()
		header = format.FastHeader()
	} else {
		kdfParams = crypto.DefaultKDFParams()
		header = format.DefaultHeader()
	}

	header.Algorithm = algorithm
	header.Comment = comment

	// Encrypt the key
	fmt.Printf("🔒 Mengenkripsi dengan %s...\n", algorithm)
	result, err := crypto.Encrypt(keyData, passphrase, algorithm, kdfParams)
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
	fmt.Printf("💾 Menyimpan file terenkripsi ke %s...\n", outputPath)
	if err := storage.SaveEncryptedFile(outputPath, encFile); err != nil {
		return fmt.Errorf("failed to save encrypted file: %w", err)
	}

	// Step 8: GitHub integration (optional)
	fmt.Println()
	githubUpload := false
	cfg, err := config.LoadConfig()
	if err == nil && cfg.IsGitHubConfigured() {
		fmt.Println("☁️  Step 8: Upload ke GitHub")
		github.PrintInfo("GitHub sudah dikonfigurasi!")
		fmt.Printf("📂 Repository: %s/%s\n", cfg.GitHub.RepoOwner, cfg.GitHub.RepoName)
		fmt.Print("❓ Upload backup ke GitHub? (Y/n): ")
		var upload string
		fmt.Scanln(&upload)
		if upload == "" || upload == "y" || upload == "Y" {
			githubUpload = true
		}
	} else {
		fmt.Println("☁️  Step 8: GitHub Integration (Opsional)")
		fmt.Print("❓ Ingin setup GitHub untuk backup otomatis? (y/N): ")
		var setup string
		fmt.Scanln(&setup)
		if setup == "y" || setup == "Y" {
			github.PrintInfo("Menjalankan setup GitHub...")
			// We'll just inform them to run the command manually for now
			github.PrintInfo("Jalankan 'sshhades github login' untuk setup GitHub integration")
		}
	}

	// Upload to GitHub if requested
	if githubUpload {
		fmt.Println("📤 Mengupload ke GitHub...")
		if err := uploadToGitHub(outputPath, comment); err != nil {
			github.PrintError(fmt.Sprintf("Upload gagal: %v", err))
			github.PrintInfo("Backup tersimpan lokal, tapi tidak terupload ke GitHub")
		} else {
			github.PrintSuccess("✅ Berhasil diupload ke GitHub!")
		}
	}

	// Success summary
	fmt.Println()
	fmt.Println("🎉 Backup Berhasil!")
	fmt.Println("=" + strings.Repeat("=", 40))
	absPath, _ := filepath.Abs(outputPath)
	fmt.Printf("📁 File: %s\n", absPath)
	fmt.Printf("🔒 Algoritma: %s\n", algorithm)
	fmt.Printf("💬 Komentar: %s\n", comment)
	
	if fastMode {
		fmt.Printf("⚡ Mode: Development (cepat, %d iterasi)\n", kdfParams.Iterations)
	} else {
		fmt.Printf("🛡️  Mode: Production (aman, %d iterasi)\n", kdfParams.Iterations)
	}
	
	fmt.Printf("📊 Ukuran: %d bytes\n", len(encFile.Ciphertext))
	fmt.Println()
	fmt.Println("💡 Tips:")
	fmt.Println("   • Simpan passphrase dengan aman")
	fmt.Println("   • Backup file .enc ini ke cloud storage")
	fmt.Printf("   • Untuk restore: sshhades restore -i %s -o <target>\n", filepath.Base(outputPath))

	return nil
}