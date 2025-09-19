# SSH Hades - Makefile for cross-platform builds

# Build variables
BINARY_NAME=sshhades
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%I:%M:%S%p')
GIT_COMMIT=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)"

# Build output directory
DIST_DIR=dist
BIN_DIR=bin

# Supported platforms
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Default target
.PHONY: all
all: clean build

# Development build (current platform)
.PHONY: dev
dev: clean-bin
	@echo "Building development version..."
	@mkdir -p $(BIN_DIR)
	@go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/sshhades
	@echo "✓ Development build complete: $(BIN_DIR)/$(BINARY_NAME)"

# Cross-platform builds
.PHONY: build
build: clean-dist
	@echo "Building $(BINARY_NAME) v$(VERSION) for multiple platforms..."
	@mkdir -p $(DIST_DIR)
	@$(foreach platform,$(PLATFORMS),\
		$(call build_platform,$(platform)))
	@echo "✓ Cross-platform builds complete in $(DIST_DIR)/"

# Build function for each platform
define build_platform
	$(eval GOOS=$(word 1,$(subst /, ,$(1))))
	$(eval GOARCH=$(word 2,$(subst /, ,$(1))))
	$(eval OUTPUT=$(DIST_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(if $(filter windows,$(GOOS)),.exe))
	@echo "  Building for $(GOOS)/$(GOARCH)..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o $(OUTPUT) ./cmd/sshhades
endef

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...
	@echo "✓ All tests passed"

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p coverage
	@go test -v -race -coverprofile=coverage/coverage.out ./...
	@go tool cover -html=coverage/coverage.out -o coverage/coverage.html
	@echo "✓ Coverage report generated: coverage/coverage.html"

# Security-focused tests
.PHONY: test-security
test-security:
	@echo "Running security tests..."
	@go test -v -tags=security ./internal/crypto/...
	@echo "✓ Security tests passed"

# Integration tests
.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	@go test -v -tags=integration ./...
	@echo "✓ Integration tests passed"

# Benchmark tests
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./internal/crypto/...

# Install to system (Linux/macOS)
.PHONY: install
install: dev
	@echo "Installing to /usr/local/bin..."
	@sudo cp $(BIN_DIR)/$(BINARY_NAME) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "✓ Installed: /usr/local/bin/$(BINARY_NAME)"

# Uninstall from system
.PHONY: uninstall
uninstall:
	@echo "Removing from /usr/local/bin..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✓ Uninstalled"

# Clean build artifacts
.PHONY: clean
clean: clean-bin clean-dist clean-coverage

.PHONY: clean-bin
clean-bin:
	@rm -rf $(BIN_DIR)

.PHONY: clean-dist
clean-dist:
	@rm -rf $(DIST_DIR)

.PHONY: clean-coverage
clean-coverage:
	@rm -rf coverage

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@goimports -w .
	@echo "✓ Code formatted"

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	@golangci-lint run
	@echo "✓ Linting passed"

# Security audit
.PHONY: audit
audit:
	@echo "Running security audit..."
	@go list -json -m all | nancy sleuth
	@gosec ./...
	@echo "✓ Security audit complete"

# Update dependencies
.PHONY: deps-update
deps-update:
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy
	@echo "✓ Dependencies updated"

# Download dependencies
.PHONY: deps-download
deps-download:
	@echo "Downloading dependencies..."
	@go mod download
	@echo "✓ Dependencies downloaded"

# Verify dependencies
.PHONY: deps-verify
deps-verify:
	@echo "Verifying dependencies..."
	@go mod verify
	@echo "✓ Dependencies verified"

# Run development server with file watching (requires entr)
.PHONY: watch
watch:
	@echo "Watching for changes..."
	@find . -name "*.go" | entr -r make dev

# Show version information
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"

# Show help
.PHONY: help
help:
	@echo "SSH Hades - Available Make targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  dev           Build for current platform ($(BIN_DIR)/)"
	@echo "  build         Cross-platform builds ($(DIST_DIR)/)"
	@echo "  clean         Clean all build artifacts"
	@echo ""
	@echo "Test targets:"
	@echo "  test          Run all tests"
	@echo "  test-coverage Run tests with coverage report"
	@echo "  test-security Run security-focused tests"
	@echo "  test-integration Run integration tests"
	@echo "  bench         Run benchmarks"
	@echo ""
	@echo "Install targets:"
	@echo "  install       Install to /usr/local/bin"
	@echo "  uninstall     Remove from /usr/local/bin"
	@echo ""
	@echo "Code quality:"
	@echo "  fmt           Format code"
	@echo "  lint          Lint code"
	@echo "  audit         Security audit"
	@echo ""
	@echo "Dependencies:"
	@echo "  deps-download Download dependencies"
	@echo "  deps-update   Update dependencies"
	@echo "  deps-verify   Verify dependencies"
	@echo ""
	@echo "Development:"
	@echo "  watch         Watch for changes and rebuild"
	@echo "  version       Show version information"
	@echo "  help          Show this help"

# Check required tools
.PHONY: check-tools
check-tools:
	@echo "Checking required tools..."
	@command -v go >/dev/null 2>&1 || { echo "Go is required but not installed"; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "Git is required but not installed"; exit 1; }
	@echo "✓ Required tools available"