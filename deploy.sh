#!/bin/bash

# RDS Security Group Updater Deployment Script
# This script builds and deploys the unified Lambda function with ARM64 architecture and Basic Auth

set -e

echo "🚀 Starting deployment of RDS Security Group Updater (ARM64 Unified + Auth)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
print_status "Checking prerequisites..."

if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

if ! command -v sam &> /dev/null; then
    print_error "SAM CLI is not installed or not in PATH"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    print_error "AWS CLI is not installed or not in PATH"
    exit 1
fi

print_success "All prerequisites are available"

# Check Go version
GO_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | head -1)
print_status "Using Go version: $GO_VERSION"

# Clean previous builds
print_status "Cleaning previous builds..."
make clean

# Download dependencies
print_status "Downloading Go dependencies..."
make deps

# Run code quality checks
print_status "Running code quality checks..."
if make fmt; then
    print_success "Code formatting completed"
else
    print_warning "Code formatting had issues"
fi

if make vet; then
    print_success "Code vetting completed"
else
    print_warning "Code vetting found issues"
fi

# Build for ARM64
print_status "Building unified Lambda function for ARM64..."
if make build; then
    print_success "ARM64 build completed successfully"
else
    print_error "Build failed"
    exit 1
fi

# Validate SAM template
print_status "Validating SAM template..."
if make validate; then
    print_success "SAM template is valid"
else
    print_error "SAM template validation failed"
    exit 1
fi

# Check if samconfig.toml exists
if [ ! -f "samconfig.toml" ]; then
    print_warning "samconfig.toml not found. You'll need to provide deployment parameters."
    if [ -f "samconfig.toml.example" ]; then
        print_status "Example configuration available at samconfig.toml.example"
        echo ""
        echo "📝 Required parameters for deployment:"
        echo "  • SecurityGroupId: The security group ID to manage"
        echo "  • S3BucketName: Unique bucket name for state storage"
        echo "  • BasicAuthUsername: Username for HTTP authentication (default: admin)"
        echo "  • BasicAuthPassword: Password for HTTP authentication (min 8 chars)"
        echo ""
        echo "Copy and modify the example configuration:"
        echo "  cp samconfig.toml.example samconfig.toml"
        echo "  # Edit samconfig.toml with your parameters"
        echo ""
    fi
    
    # Interactive deployment
    print_status "Starting guided deployment..."
    if sam build && sam deploy --guided; then
        print_success "Guided deployment completed"
    else
        print_error "Deployment failed"
        exit 1
    fi
else
    # Fast deployment with existing config
    print_status "Using existing samconfig.toml for fast deployment..."
    if make deploy-fast; then
        print_success "Fast deployment completed"
    else
        print_error "Fast deployment failed"
        exit 1
    fi
fi

# Get stack outputs
print_status "Retrieving stack outputs..."
STACK_NAME=$(grep -E '^stack_name\s*=' samconfig.toml 2>/dev/null | cut -d'=' -f2 | tr -d ' "' || echo "rds-sg-updater")

if aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs' --output table 2>/dev/null; then
    print_success "Stack outputs retrieved"
else
    print_warning "Could not retrieve stack outputs. Stack name might be different."
fi

# Get Function URL and Auth info
print_status "Retrieving Function URL and authentication details..."
FUNCTION_URL=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`FunctionUrl`].OutputValue' --output text 2>/dev/null || echo "Not found")
AUTH_USERNAME=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`BasicAuthUsername`].OutputValue' --output text 2>/dev/null || echo "admin")

if [ "$FUNCTION_URL" != "Not found" ]; then
    print_success "Function URL: $FUNCTION_URL"
    print_success "Auth Username: $AUTH_USERNAME"
    echo ""
    echo "🎉 Deployment completed successfully!"
    echo ""
    echo "🔐 Authentication Information:"
    echo "  Username: $AUTH_USERNAME"
    echo "  Password: [Set during deployment - check your samconfig.toml]"
    echo ""
    echo "📋 Next steps:"
    echo "  1. Test the Function URL with authentication:"
    echo "     curl -u $AUTH_USERNAME:YourPassword '$FUNCTION_URL'"
    echo ""
    echo "  2. Check function logs:"
    echo "     make logs"
    echo ""
    echo "  3. Test reset functionality:"
    echo "     make local-invoke-reset"
    echo ""
    echo "💡 API Usage Examples:"
    echo "  • Grant access:"
    echo "    curl -u $AUTH_USERNAME:YourPassword '$FUNCTION_URL'"
    echo ""
    echo "  • Remove access:"
    echo "    curl -u $AUTH_USERNAME:YourPassword -X POST '$FUNCTION_URL' \\"
    echo "         -H 'Content-Type: application/json' \\"
    echo "         -d '{\"action\": \"remove_access\"}'"
    echo ""
    echo "  • Check status:"
    echo "    curl -u $AUTH_USERNAME:YourPassword -X POST '$FUNCTION_URL' \\"
    echo "         -H 'Content-Type: application/json' \\"
    echo "         -d '{\"action\": \"status\"}'"
    echo ""
    echo "  • Manual reset:"
    echo "    curl -u $AUTH_USERNAME:YourPassword -X POST '$FUNCTION_URL' \\"
    echo "         -H 'Content-Type: application/json' \\"
    echo "         -d '{\"action\": \"reset\"}'"
    echo ""
    echo "🔒 Security Notes:"
    echo "  • All endpoints require HTTP Basic Authentication"
    echo "  • Replace 'YourPassword' with your actual password"
    echo "  • EventBridge cron jobs bypass authentication (internal AWS traffic)"
    echo "  • Consider using environment variables for credentials in scripts"
    echo ""
    echo "📊 Weekly Reset Schedule: Every Sunday at 2:00 AM UTC"
else
    print_warning "Could not retrieve Function URL from stack outputs"
fi

print_success "Deployment script completed" 