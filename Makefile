# Makefile for hm-lib
# Go module: hostingmaster.io/hm-lib

GO := go
GOLANGCI_LINT := golangci-lint
MODULE := hostingmaster.io/hm-lib

# Directories
PKG_DIR := ./...

# Linter configuration
GOLANGCI_TEMPLATE := ./templates/golangci-linter/golangci.yaml
GOLANGCI_LOCAL_CONFIG := .golangci.local.yaml
GOLANGCI_OUTPUT_CONFIG := .golangci.yaml
YQ_CMD := yq

# Tool versions
GOLANGCI_VERSION := v2.11.4

.PHONY: all test test-race test-cover lint lint-fix lint-config clean tidy generate help

# Default target
all: test lint

# Run tests
test: tidy
	$(GO) test -v $(PKG_DIR)

# Run tests with race detector
test-race: tidy
	$(GO) test -race -v $(PKG_DIR)

# Run tests with coverage
test-cover: tidy
	$(GO) test -coverprofile=coverage.out -v $(PKG_DIR)
	$(GO) tool cover -html=coverage.out -o coverage.html

# Prepare golangci-linter configuration
lint-config:
	@echo "--- Preparing golangci-linter configuration ---"
	@if [ ! -f "$(GOLANGCI_TEMPLATE)" ]; then \
		echo "Error: Template config not found at $(GOLANGCI_TEMPLATE)"; \
		exit 1; \
	fi
	@if [ -f "$(GOLANGCI_LOCAL_CONFIG)" ]; then \
		echo "Merging template with local config from $(GOLANGCI_LOCAL_CONFIG)"; \
		$(YQ_CMD) eval-all '. as $$item ireduce ({}; . *+ $$item)' \
			"$(GOLANGCI_TEMPLATE)" \
			"$(GOLANGCI_LOCAL_CONFIG)" > "$(GOLANGCI_OUTPUT_CONFIG)"; \
		echo "  Merge completed -> $(GOLANGCI_OUTPUT_CONFIG)"; \
	else \
		echo "No local config found, copying template"; \
		cp "$(GOLANGCI_TEMPLATE)" "$(GOLANGCI_OUTPUT_CONFIG)"; \
		echo "  Template copied to $(GOLANGCI_OUTPUT_CONFIG)"; \
	fi
	@echo "Done! Linter config ready at $(GOLANGCI_OUTPUT_CONFIG)"

# Run linter
lint: lint-config
	@echo "Running golangci-lint..."
	$(GOLANGCI_LINT) run --config $(GOLANGCI_OUTPUT_CONFIG) ./...

# Fix lint issues
lint-fix:
	@echo "Fixing lint issues..."
	$(GOLANGCI_LINT) run --config $(GOLANGCI_OUTPUT_CONFIG) --fix ./...

# Clean build artifacts
clean:
	rm -f coverage.out coverage.html

# Tidy go modules
tidy:
	$(GO) mod tidy

# Generate code (placeholder for go generate if needed)
generate:
	$(GO) generate $(PKG_DIR)

# Show help
help:
	@echo "Available targets:"
	@echo "  all           - Run tests and linter (default)"
	@echo "  test          - Run all tests"
	@echo "  test-race     - Run tests with race detector"
	@echo "  test-cover    - Run tests with coverage report"
	@echo "  lint          - Run golangci-lint"
	@echo "  lint-fix      - Fix lint issues"
	@echo "  lint-config   - Prepare golangci-linter configuration"
	@echo "  clean         - Remove build artifacts"
	@echo "  tidy          - Run go mod tidy"
	@echo "  generate      - Run go generate"
	@echo "  help          - Show this help message"
