.PHONY: build clean deploy test lint

# Variables for ARM64 build
GOOS=linux
GOARCH=arm64
CGO_ENABLED=0

# Build directory
BUILD_DIR=bin

# Go modules
GO_MOD=go.mod

# Default target
all: clean build

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out

# Build the unified Lambda function
build:
	@echo "Building Security Group Authorizer Lambda function for Amazon Linux ARM64..."
	mkdir -p $(BUILD_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build -ldflags="-s -w" -o $(BUILD_DIR)/bootstrap ./cmd/main
	@echo "Build completed successfully!"
	cp ./bin/bootstrap $(ARTIFACTS_DIR)/bootstrap

build-SGAuthorizerFunction:
	make build

# Initialize Go modules
init:
	@echo "Initializing Go modules..."
	go mod init lambda-sg-authorizer
	go mod tidy

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run ./...

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	go vet ./...

# Run all checks
check: fmt vet lint test

# Build for development (local)
build-dev:
	@echo "Building for development..."
	go build -o $(BUILD_DIR)/main-dev ./cmd/main

# Deploy using SAM
deploy:
	@echo "Deploying with SAM..."
	sam build --use-makefile
	sam deploy --guided

# Deploy without prompts (requires samconfig.toml)
deploy-fast:
	@echo "Fast deploying with SAM..."
	sam build --use-makefile
	sam deploy

# Package for deployment
package:
	@echo "Packaging application..."
	sam build --use-makefile
	sam package --s3-bucket $(S3_BUCKET) --output-template-file packaged-template.yaml

# Validate SAM template
validate:
	@echo "Validating SAM template..."
	sam validate

# Local testing
local-start:
	@echo "Starting local API..."
	sam local start-api

# Invoke function locally
local-invoke:
	@echo "Invoking function locally..."
	sam local invoke SGAuthorizerFunction

# Invoke function locally with reset event
local-invoke-reset:
	@echo "Invoking function locally with reset event..."
	echo '{"source": "eventbridge", "action": "reset"}' | sam local invoke SGAuthorizerFunction

# Show logs
logs:
	@echo "Showing function logs..."
	sam logs -n SGAuthorizerFunction --stack-name sg-authorizer

# Help
help:
	@echo "Available targets:"
	@echo "  build              - Build Lambda function for Amazon Linux ARM64"
	@echo "  build-dev          - Build for local development"
	@echo "  clean              - Clean build artifacts"
	@echo "  init               - Initialize Go modules"
	@echo "  deps               - Download dependencies"
	@echo "  test               - Run tests"
	@echo "  test-coverage      - Run tests with coverage"
	@echo "  lint               - Lint code"
	@echo "  fmt                - Format code"
	@echo "  vet                - Vet code"
	@echo "  check              - Run fmt, vet, lint, and test"
	@echo "  deploy             - Deploy with SAM (guided)"
	@echo "  deploy-fast        - Deploy with SAM (fast)"
	@echo "  package            - Package for deployment"
	@echo "  validate           - Validate SAM template"
	@echo "  local-start        - Start local API"
	@echo "  local-invoke       - Invoke function locally"
	@echo "  local-invoke-reset - Invoke function locally with reset event"
	@echo "  logs               - Show function logs"
	@echo "  help               - Show this help"
