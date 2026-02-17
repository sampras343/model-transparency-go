# Makefile for model-transparency-go
# Provides targets for building, testing, and coverage

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOCLEAN=$(GOCMD) clean
GOVET=$(GOCMD) vet
GOFMT=gofmt

# Binary name
BINARY_NAME=model-signing
BINARY_PATH=./cmd/model-signing

# Build output directory
BUILD_DIR=./build

# Test parameters
TEST_PACKAGES=./cmd/... ./pkg/...
TEST_TIMEOUT=300s
COVERAGE_DIR=./coverage
COVERAGE_FILE=$(COVERAGE_DIR)/coverage.out
COVERAGE_HTML=$(COVERAGE_DIR)/coverage.html

# Colors for output
COLOR_RESET=\033[0m
COLOR_BOLD=\033[1m
COLOR_GREEN=\033[32m
COLOR_YELLOW=\033[33m
COLOR_BLUE=\033[34m

.PHONY: all build clean test test-unit test-ci test-coverage coverage-report help deps vet fmt fmt-check lint \
	docker-build podman-build container-build build-test-binary build-test-binary-otel \
	mod-tidy-check license-check docs

## help: Display this help message
help:
	@echo -e "$(COLOR_BOLD)model-transparency-go Makefile$(COLOR_RESET)"
	@echo ""
	@echo -e "$(COLOR_BOLD)Available targets:$(COLOR_RESET)"
	@echo -e "  $(COLOR_GREEN)build$(COLOR_RESET)           - Build the binary"
	@echo -e "  $(COLOR_GREEN)clean$(COLOR_RESET)           - Clean build artifacts and coverage reports"
	@echo -e "  $(COLOR_GREEN)test$(COLOR_RESET)            - Run all tests"
	@echo -e "  $(COLOR_GREEN)test-unit$(COLOR_RESET)       - Run unit tests only (faster)"
	@echo -e "  $(COLOR_GREEN)test-coverage$(COLOR_RESET)   - Run tests with coverage report"
	@echo -e "  $(COLOR_GREEN)coverage-report$(COLOR_RESET) - Generate HTML coverage report"
	@echo -e "  $(COLOR_GREEN)vet$(COLOR_RESET)             - Run go vet"
	@echo -e "  $(COLOR_GREEN)fmt$(COLOR_RESET)             - Format code with go fmt"
	@echo -e "  $(COLOR_GREEN)deps$(COLOR_RESET)            - Download dependencies"
	@echo -e "  $(COLOR_GREEN)lint$(COLOR_RESET)            - Run linters (vet + fmt check)"
	@echo -e "  $(COLOR_GREEN)test-ci$(COLOR_RESET)         - Run tests with race detector and coverage (CI)"
	@echo -e "  $(COLOR_GREEN)mod-tidy-check$(COLOR_RESET)  - Verify go.mod and go.sum are tidy"
	@echo -e "  $(COLOR_GREEN)license-check$(COLOR_RESET)   - Check license headers"
	@echo -e "  $(COLOR_GREEN)docs$(COLOR_RESET)            - Generate API documentation"
	@echo -e "  $(COLOR_GREEN)container-build$(COLOR_RESET) - Build and verify container image"
	@echo -e "  $(COLOR_GREEN)build-test-binary$(COLOR_RESET) - Build binary for integration tests"
	@echo ""
	@echo -e "$(COLOR_BOLD)Examples:$(COLOR_RESET)"
	@echo "  make build              # Build the binary"
	@echo "  make test               # Run all tests"
	@echo "  make test-coverage      # Run tests and generate coverage report"
	@echo "  make coverage-report    # View coverage report in browser"
	@echo ""

## all: Build binary and run tests
all: deps vet test build
	@echo "$(COLOR_GREEN)✓ Build and tests completed successfully$(COLOR_RESET)"

## build: Build the binary
build:
	@echo "$(COLOR_BLUE)Building $(BINARY_NAME)...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) -v $(BINARY_PATH)
	@echo "$(COLOR_GREEN)✓ Binary built: $(BUILD_DIR)/$(BINARY_NAME)$(COLOR_RESET)"

## build-linux: Build for Linux
build-linux:
	@echo "$(COLOR_BLUE)Building $(BINARY_NAME) for Linux...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 -v $(BINARY_PATH)
	@echo "$(COLOR_GREEN)✓ Binary built: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64$(COLOR_RESET)"

## build-macos: Build for macOS
build-macos:
	@echo "$(COLOR_BLUE)Building $(BINARY_NAME) for macOS...$(COLOR_RESET)"
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 -v $(BINARY_PATH)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 -v $(BINARY_PATH)
	@echo "$(COLOR_GREEN)✓ Binaries built: $(BUILD_DIR)/$(BINARY_NAME)-darwin-*$(COLOR_RESET)"

## clean: Clean build artifacts and coverage reports
clean:
	@echo "$(COLOR_YELLOW)Cleaning build artifacts...$(COLOR_RESET)"
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)
	@echo "$(COLOR_GREEN)✓ Cleaned$(COLOR_RESET)"

## deps: Download dependencies
deps:
	@echo "$(COLOR_BLUE)Downloading dependencies...$(COLOR_RESET)"
	$(GOGET) -v ./...
	$(GOMOD) tidy
	@echo "$(COLOR_GREEN)✓ Dependencies downloaded$(COLOR_RESET)"

## test: Run all tests
test:
	@echo "$(COLOR_BLUE)Running all tests...$(COLOR_RESET)"
	$(GOTEST) -v -timeout $(TEST_TIMEOUT) $(TEST_PACKAGES)
	@echo "$(COLOR_GREEN)✓ All tests passed$(COLOR_RESET)"

## test-unit: Run unit tests (faster, no integration tests)
test-unit:
	@echo "$(COLOR_BLUE)Running unit tests...$(COLOR_RESET)"
	$(GOTEST) -v -short -timeout $(TEST_TIMEOUT) $(TEST_PACKAGES)
	@echo "$(COLOR_GREEN)✓ Unit tests passed$(COLOR_RESET)"

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "$(COLOR_BLUE)Running tests with coverage...$(COLOR_RESET)"
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -timeout $(TEST_TIMEOUT) -coverprofile=$(COVERAGE_FILE) -covermode=atomic $(TEST_PACKAGES)
	@echo "$(COLOR_GREEN)✓ Tests completed$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Coverage Summary:$(COLOR_RESET)"
	@$(GOCMD) tool cover -func=$(COVERAGE_FILE) | tail -1
	@echo ""
	@echo "$(COLOR_BLUE)Coverage report saved to: $(COVERAGE_FILE)$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)Run 'make coverage-report' to view HTML report$(COLOR_RESET)"

## coverage-report: Generate and open HTML coverage report
coverage-report: test-coverage
	@echo "$(COLOR_BLUE)Generating HTML coverage report...$(COLOR_RESET)"
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "$(COLOR_GREEN)✓ HTML coverage report generated: $(COVERAGE_HTML)$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BOLD)Opening coverage report in browser...$(COLOR_RESET)"
	@if command -v xdg-open > /dev/null 2>&1; then \
		xdg-open $(COVERAGE_HTML); \
	elif command -v open > /dev/null 2>&1; then \
		open $(COVERAGE_HTML); \
	else \
		echo "$(COLOR_YELLOW)Please open $(COVERAGE_HTML) manually$(COLOR_RESET)"; \
	fi

## coverage-func: Show coverage by function
coverage-func:
	@if [ ! -f $(COVERAGE_FILE) ]; then \
		echo "$(COLOR_YELLOW)Coverage file not found. Run 'make test-coverage' first$(COLOR_RESET)"; \
		exit 1; \
	fi
	@echo "$(COLOR_BOLD)Coverage by Function:$(COLOR_RESET)"
	@$(GOCMD) tool cover -func=$(COVERAGE_FILE)

## vet: Run go vet
vet:
	@echo "$(COLOR_BLUE)Running go vet...$(COLOR_RESET)"
	$(GOVET) $(TEST_PACKAGES)
	@echo "$(COLOR_GREEN)✓ go vet passed$(COLOR_RESET)"

## fmt: Format code with go fmt
fmt:
	@echo "$(COLOR_BLUE)Formatting code...$(COLOR_RESET)"
	$(GOCMD) fmt $(TEST_PACKAGES)
	@echo "$(COLOR_GREEN)✓ Code formatted$(COLOR_RESET)"

## fmt-check: Check if code is formatted
fmt-check:
	@echo "$(COLOR_BLUE)Checking code formatting...$(COLOR_RESET)"
	@UNFORMATTED=$$(find . -name '*.go' -not -path './examples/*' -not -path './vendor/*' | xargs $(GOFMT) -l); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "$(COLOR_YELLOW)The following files are not formatted:$(COLOR_RESET)"; \
		echo "$$UNFORMATTED"; \
		echo "$(COLOR_YELLOW)Run 'make fmt' to format them$(COLOR_RESET)"; \
		exit 1; \
	fi
	@echo "$(COLOR_GREEN)✓ Code is properly formatted$(COLOR_RESET)"

## lint: Run linters
lint: vet fmt-check
	@echo "$(COLOR_GREEN)✓ Linting passed$(COLOR_RESET)"

## test-verbose: Run tests with verbose output
test-verbose:
	@echo "$(COLOR_BLUE)Running tests with verbose output...$(COLOR_RESET)"
	$(GOTEST) -v -timeout $(TEST_TIMEOUT) $(TEST_PACKAGES) 2>&1 | tee test-output.log
	@echo "$(COLOR_GREEN)✓ Test output saved to test-output.log$(COLOR_RESET)"

## test-race: Run tests with race detector
test-race:
	@echo "$(COLOR_BLUE)Running tests with race detector...$(COLOR_RESET)"
	$(GOTEST) -race -timeout $(TEST_TIMEOUT) $(TEST_PACKAGES)
	@echo "$(COLOR_GREEN)✓ Race tests passed$(COLOR_RESET)"

## test-bench: Run benchmarks
test-bench:
	@echo "$(COLOR_BLUE)Running benchmarks...$(COLOR_RESET)"
	$(GOTEST) -bench=. -benchmem $(TEST_PACKAGES)

## install: Install the binary to $GOPATH/bin
install: build
	@echo "$(COLOR_BLUE)Installing $(BINARY_NAME)...$(COLOR_RESET)"
	$(GOCMD) install $(BINARY_PATH)
	@echo "$(COLOR_GREEN)✓ Installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)$(COLOR_RESET)"

## run: Build and run the binary
run: build
	@echo "$(COLOR_BLUE)Running $(BINARY_NAME)...$(COLOR_RESET)"
	$(BUILD_DIR)/$(BINARY_NAME)

## ci: Run CI pipeline (lint, test, build)
ci: deps lint test-coverage build
	@echo "$(COLOR_GREEN)✓ CI pipeline completed successfully$(COLOR_RESET)"

## test-ci: Run tests with race detector and coverage (CI mode)
test-ci:
	@echo "$(COLOR_BLUE)Running tests with race detector and coverage...$(COLOR_RESET)"
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic $(TEST_PACKAGES)
	@echo "$(COLOR_GREEN)✓ CI tests passed$(COLOR_RESET)"

## mod-tidy-check: Verify go.mod and go.sum are tidy
mod-tidy-check:
	@echo "$(COLOR_BLUE)Checking go.mod and go.sum...$(COLOR_RESET)"
	$(GOMOD) tidy
	@if ! git diff --quiet go.mod go.sum; then \
		echo "$(COLOR_YELLOW)go.mod or go.sum is not tidy. Run 'go mod tidy'.$(COLOR_RESET)"; \
		git diff go.mod go.sum; \
		exit 1; \
	fi
	@echo "$(COLOR_GREEN)✓ go.mod and go.sum are tidy$(COLOR_RESET)"

## license-check: Check license headers
license-check:
	@echo "$(COLOR_BLUE)Checking license headers...$(COLOR_RESET)"
	go install github.com/google/addlicense@v1.1.1
	addlicense -check -l apache -c 'The Sigstore Authors' -ignore "third_party/**" -ignore "**/*.sh" -v *
	@echo "$(COLOR_GREEN)✓ License headers are correct$(COLOR_RESET)"

## docs: Generate API documentation
docs:
	@echo "$(COLOR_BLUE)Generating documentation...$(COLOR_RESET)"
	go install go.abhg.dev/doc2go@latest
	doc2go -out ./html ./...
	@echo "$(COLOR_GREEN)✓ Documentation generated in ./html/$(COLOR_RESET)"

## build-test-binary: Build binary for integration tests
build-test-binary:
	@echo "$(COLOR_BLUE)Building test binary...$(COLOR_RESET)"
	$(GOBUILD) -o scripts/tests/$(BINARY_NAME) $(BINARY_PATH)
	@echo "$(COLOR_GREEN)✓ Test binary built: scripts/tests/$(BINARY_NAME)$(COLOR_RESET)"

## build-test-binary-otel: Build binary with OTel for integration tests
build-test-binary-otel:
	@echo "$(COLOR_BLUE)Building test binary with OTel...$(COLOR_RESET)"
	$(GOBUILD) -tags=otel -o scripts/tests/$(BINARY_NAME) $(BINARY_PATH)
	@echo "$(COLOR_GREEN)✓ OTel test binary built: scripts/tests/$(BINARY_NAME)$(COLOR_RESET)"

## container-build: Build and verify container image
container-build:
	@echo "$(COLOR_BLUE)Building container image...$(COLOR_RESET)"
	docker build -t model-signing:test -f Containerfile .
	docker run --rm model-signing:test --help
	@echo "$(COLOR_GREEN)✓ Container image built and verified$(COLOR_RESET)"

## docker-build: Build container image with Docker
docker-build:
	@echo "$(COLOR_BLUE)Building container image with Docker...$(COLOR_RESET)"
	docker build -t model-signing:latest -f Containerfile .
	@echo "$(COLOR_GREEN)✓ Docker image built$(COLOR_RESET)"

## podman-build: Build container image with Podman
podman-build:
	@echo "$(COLOR_BLUE)Building container image with Podman...$(COLOR_RESET)"
	podman build -t model-signing:latest -f Containerfile .
	@echo "$(COLOR_GREEN)✓ Podman image built$(COLOR_RESET)"

## mod-update: Update all dependencies
mod-update:
	@echo "$(COLOR_BLUE)Updating dependencies...$(COLOR_RESET)"
	$(GOGET) -u ./...
	$(GOMOD) tidy
	@echo "$(COLOR_GREEN)✓ Dependencies updated$(COLOR_RESET)"

## mod-verify: Verify dependencies
mod-verify:
	@echo "$(COLOR_BLUE)Verifying dependencies...$(COLOR_RESET)"
	$(GOMOD) verify
	@echo "$(COLOR_GREEN)✓ Dependencies verified$(COLOR_RESET)"

# Default target
.DEFAULT_GOAL := help
