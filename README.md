# SSH Hades

A secure Go CLI tool for encrypting and backing up SSH keys using AES-256-GCM encryption with Argon2id key derivation.

## Performance Modes

SSH Hades offers two performance modes to balance security and speed:

### Production Mode (Default)
- **Argon2id iterations**: 100,000
- **Security**: Maximum protection against brute force attacks
- **Speed**: Slower (~3-5 seconds for encryption/decryption)
- **Use case**: Production environments, long-term storage

### Development Mode (Fast)
- **Argon2id iterations**: 1,000
- **Security**: Reduced protection (still cryptographically secure)
- **Speed**: Much faster (~0.1-0.5 seconds)
- **Use case**: Development, testing, frequent operations

```bash
# Use fast mode with any command
sshhades backup --input ~/.ssh/id_ed25519 --output backup.enc --fast
sshhades restore --input backup.enc --output restored_key --fast

# Production mode (default - no flag needed)
sshhades backup --input ~/.ssh/id_ed25519 --output backup.enc
```

## Encryption Algorithms

### AES-256-GCM (Default)
- **Standard**: NIST-approved, widely adopted
- **Performance**: Fast on hardware with AES acceleration
- **Compatibility**: Excellent across all platforms

### ChaCha20-Poly1305
- **Standard**: RFC 8439, modern AEAD cipher
- **Performance**: Consistent across all hardware
- **Benefits**: Resistant to timing attacks, software-optimized

```bash
# Use ChaCha20-Poly1305
sshhades backup --input ~/.ssh/id_ed25519 --output backup.enc --algorithm chacha20

# Use AES-256-GCM (default)
sshhades backup --input ~/.ssh/id_ed25519 --output backup.enc --algorithm aes
```

- **🔒 Multiple Encryption Algorithms**: AES-256-GCM and ChaCha20-Poly1305
- **🔑 Secure KDF**: Argon2id key derivation function
- **⚡ Performance Modes**: Production (secure) vs Development (fast) modes
- **🎯 Interactive Mode**: User-friendly wizard for easy SSH key backup
- **📦 Single Binary**: Self-contained executable, no external dependencies
- **🌍 Cross-Platform**: Linux, Windows, macOS support
- **🐙 GitHub Integration**: Automated backup to private repositories
- **🛡️ Security-First**: Memory clearing, input validation, secure defaults
- **📋 Smart File Selection**: Interactive selection from ~/.ssh directory

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/sshhades/sshhades/releases):

```bash
# Linux/macOS
curl -L https://github.com/sshhades/sshhades/releases/latest/download/sshhades-linux-amd64 -o sshhades
chmod +x sshhades
sudo mv sshhades /usr/local/bin/

# Or use the Makefile
make install
```

### Build from Source

```bash
git clone https://github.com/sshhades/sshhades
cd sshhades
make build
```

## Quick Start

### Interactive Mode (Recommended for Beginners)

```bash
# Run interactive wizard - easiest way to get started
sshhades interactive

# Or use shortcuts
sshhades i
sshhades wizard
```

The interactive mode will guide you through:
- 📁 Selecting SSH keys from ~/.ssh directory
- 🔒 Choosing encryption algorithm (AES-256-GCM or ChaCha20-Poly1305)
- ⚡ Performance mode selection (Production vs Development)
- 💬 Adding comments and metadata

### Manual Backup Commands

### Backup an SSH Key

```bash
# Basic backup
sshhades backup --input ~/.ssh/id_ed25519 --output ~/backups/id_ed25519.enc

# With custom comment
sshhades backup -i ~/.ssh/id_rsa -o ~/backups/id_rsa.enc --comment "Production server key"

# Backup and upload to GitHub
sshhades backup -i ~/.ssh/id_ed25519 -o id_ed25519.enc \
  --github-repo "username/ssh-backups" \
  --comment "Main development key"
```

### Restore an SSH Key

```bash
# Basic restore
sshhades restore --input ~/backups/id_ed25519.enc --output ~/.ssh/id_ed25519

# With passphrase from environment
PASSPHRASE=mysecretpass sshhades restore -i backup.enc -o ~/.ssh/id_ed25519 --passphrase-env PASSPHRASE
```

### List Available Keys

```bash
# List keys in ~/.ssh
sshhades list

# List with detailed information
sshhades list --verbose

# List keys in custom directory
sshhades list --directory ~/backups
```

### Verify Encrypted Files

```bash
# Verify file integrity
sshhades verify --input ~/backups/id_ed25519.enc
```

## Command Reference

### Global Options

- `--help, -h`: Show help
- `--version`: Show version information

### Backup Command

```bash
sshhades backup [flags]
```

**Required:**
- `--input, -i`: Path to SSH key file to backup

**Optional:**
- `--output, -o`: Output path for encrypted file (auto-generated if not specified)
- `--comment, -c`: Comment/label for the key
- `--iterations, -n`: Argon2id iterations (default: 100000)
- `--memory`: Argon2id memory usage in MB (default: 64)
- `--threads`: Argon2id parallelism (default: 4)
- `--passphrase-env`: Environment variable containing passphrase
- `--github-repo`: GitHub repository for backup (owner/repo format)
- `--github-token`: GitHub token (defaults to GITHUB_TOKEN env var)

### Restore Command

```bash
sshhades restore [flags]
```

**Required:**
- `--input, -i`: Path to encrypted SSH key file
- `--output, -o`: Path for restored SSH key file

**Optional:**
- `--passphrase-env`: Environment variable containing passphrase
- `--force`: Overwrite existing output file

### List Command

```bash
sshhades list [flags]
```

**Optional:**
- `--directory, -d`: Directory to search (defaults to ~/.ssh)
- `--verbose, -v`: Show detailed information

### Verify Command

```bash
sshhades verify [flags]
```

**Required:**
- `--input, -i`: Path to encrypted file to verify

## Security

### Encryption Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: Argon2id with configurable parameters
- **Authentication**: Built-in with GCM mode
- **Random Generation**: Cryptographically secure (`crypto/rand`)

### File Format

Encrypted files use JSON format with the following structure:

```json
{
  "header": {
    "version": "1.0",
    "algorithm": "AES-256-GCM",
    "kdf": "Argon2id",
    "iterations": 100000,
    "memory": 64,
    "threads": 4,
    "timestamp": "2023-12-01T12:00:00Z",
    "comment": "Optional description"
  },
  "salt": "base64-encoded-salt",
  "nonce": "base64-encoded-nonce",
  "ciphertext": "base64-encoded-encrypted-data",
  "tag": "base64-encoded-auth-tag"
}
```

### Security Best Practices

1. **Use strong passphrases**: Consider using a password manager
2. **Store encrypted files securely**: Use private repositories only
3. **Regular backups**: Backup your encrypted backups
4. **Verify integrity**: Use `sshhades verify` to check file integrity
5. **Clear environment**: Don't store passphrases in shell history

### GitHub Integration Security

- Uses personal access tokens with minimal `repo` scope
- Automatically creates `.gitignore` to prevent raw key commits
- Uploads only encrypted `.enc` files
- Maintains directory structure: `ssh-keys/*.enc`

## Development

### Build System

```bash
# Development build
make dev

# Cross-platform builds
make build

# Run tests
make test

# Test with coverage
make test-coverage

# Security tests
make test-security

# Clean build artifacts
make clean
```

### Testing

```bash
# All tests
make test

# Security-focused tests
make test-security

# Integration tests
make test-integration

# Benchmarks
make bench
```

## Environment Variables

- `GITHUB_TOKEN`: GitHub personal access token for repository access
- `SSH_PASSPHRASE`: Passphrase for encryption/decryption (use with `--passphrase-env`)

## Examples

### Complete Backup Workflow

```bash
# 1. Backup your main SSH key
sshhades backup \
  --input ~/.ssh/id_ed25519 \
  --output ~/secure-backups/id_ed25519.enc \
  --comment "Main development key - laptop" \
  --iterations 200000

# 2. Upload to private GitHub repository
sshhades backup \
  --input ~/.ssh/id_rsa \
  --github-repo "username/ssh-backups" \
  --comment "Server access key"

# 3. List all your keys
sshhades list --verbose

# 4. Verify backup integrity
sshhades verify --input ~/secure-backups/id_ed25519.enc
```

### Restore Workflow

```bash
# 1. Download encrypted backup (if from GitHub)
# 2. Restore to new location
sshhades restore \
  --input ./id_ed25519.enc \
  --output ~/.ssh/id_ed25519 \
  --passphrase-env SSH_PASSPHRASE

# 3. Set correct permissions (automatically handled)
# 4. Test SSH connection
ssh -i ~/.ssh/id_ed25519 user@server
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the full test suite: `make test`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Uses Go's excellent `crypto` package for cryptographic operations
- Built with [Cobra](https://github.com/spf13/cobra) for CLI interface
- Inspired by the need for secure SSH key management