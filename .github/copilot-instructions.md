# SSH Hades - AI Development Guide

SSH Hades is a Go CLI tool for encrypting and backing up SSH keys using AES-GCM encryption with optional GitHub integration.

## Project Architecture

### Core Design Philosophy
- **Security-first**: All cryptographic operations use vetted algorithms (AES-256-GCM + Argon2id KDF)
- **Single binary**: Self-contained executable with no external dependencies
- **Cross-platform**: Linux, Windows, macOS support via Go's compilation targets

### Component Structure
```
sshhades/
├── cmd/sshhades/          # Main CLI application entry point
├── internal/
│   ├── crypto/            # AES-GCM encryption + Argon2id KDF implementation
│   ├── ssh/               # SSH key file reading/writing utilities
│   ├── storage/           # File I/O operations with security checks
│   └── github/            # GitHub API integration for automated backups
├── pkg/format/            # Encrypted file format specification
├── configs/               # Configuration files and defaults
└── scripts/               # Build scripts and deployment automation
```

## Cryptographic Standards

### Encryption Stack
- **Primary**: AES-256-GCM (authenticated encryption in Go's `crypto/aes` + `crypto/cipher`)
- **KDF**: Argon2id for deriving AES keys from passphrases (`golang.org/x/crypto/argon2`)
- **File Format**: `[version]|[nonce]|[ciphertext]|[tag]` with metadata header

### Security Requirements
- Always use `crypto/rand` for random generation
- Clear sensitive data from memory with explicit zeroing
- Verify GCM authentication tags on all decryption operations
- Never store passphrases in code - use env vars or interactive prompts

## CLI Interface Patterns

### Command Structure
```bash
sshhades backup --input ~/.ssh/id_ed25519 --output ~/backups/key.enc --comment "description"
sshhades restore --input ~/backups/key.enc --output ~/.ssh/id_ed25519
sshhades list     # Show available encrypted keys
sshhades verify   # Check encrypted file integrity
```

### Flag Conventions
- Input/Output: `--input/-i`, `--output/-o`
- Security: `--iterations/-n` (Argon2id, default: 100000), `--memory`, `--threads`
- Passphrase: `--passphrase-env` (preferred), avoid `--passphrase` direct input

## Development Workflows

### Build System (Makefile)
```bash
make build        # Cross-platform builds (Linux, Windows, macOS, ARM64)
make dev          # Development build to bin/sshhades
make test         # Full test suite with security focus
make test-coverage # Coverage analysis
make install      # System installation to /usr/local/bin
```

### Testing Strategy
- Security-focused unit tests with known test vectors
- Input validation testing against malicious inputs
- Cryptographic operation verification
- Memory management testing (sensitive data clearing)

## GitHub Integration

### Repository Structure
Target private backup repos use this layout:
```
private-backups/
├── ssh-keys/
│   ├── *.enc           # Encrypted SSH keys only
│   └── metadata.json   # Key inventory and timestamps
└── .gitignore          # Prevents raw key commits
```

### API Requirements
- GitHub Personal Access Token with `repo` scope
- Environment variable: `GITHUB_TOKEN`
- Automated upload after successful encryption

## Code Style Enforcements

### Error Handling
```go
// Always wrap errors with context
return fmt.Errorf("failed to encrypt key: %w", err)

// Security-focused error handling
if err != nil {
    clearSensitiveData()
    return fmt.Errorf("operation failed: %w", err)
}
```

### Memory Management
```go
// Clear sensitive data explicitly
defer func() {
    for i := range passphrase {
        passphrase[i] = 0
    }
}()
```

## Security Considerations

### Threat Model
- File system access to encrypted files
- Memory dumps during operation
- Network interception (GitHub API)
- Social engineering for passphrases

### Implementation Notes
- Use only internal packages for sensitive operations
- Implement defense-in-depth with multiple security layers
- Regular dependency security scanning in CI/CD
- Cryptographic agility for future algorithm upgrades

## Project Status
**Current Phase**: Design and specification (`.cursor/rules/` contains detailed technical specifications)
**Implementation Status**: Planning stage - use existing `.cursor/rules/*.mdc` files as authoritative design documents