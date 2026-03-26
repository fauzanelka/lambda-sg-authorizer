# Security Group Authorizer

A serverless AWS Lambda application built with Go that dynamically manages EC2 security group rules based on client IP addresses. The application uses a **unified Lambda function** with **ARM64 architecture** that handles both Lambda Function URLs for direct HTTP access and EventBridge events for automated daily resets. **HTTP Basic Authentication** protects the Function URL endpoints.

## Features

### Core Functionality
- ✅ **Dynamic IP Whitelisting**: Automatically adds ingress rules for client IPs on a configurable port (SSH, MySQL, PostgreSQL, or any TCP service)
- ✅ **Real Client IP Detection**: Extracts real client IP from various headers (X-Forwarded-For, X-Real-IP, etc.)
- ✅ **Original State Management**: Saves and restores original security group configurations
- ✅ **Daily Reset**: Automatically resets security groups to original state every day via EventBridge
- ✅ **Comprehensive Logging**: Structured JSON logging to CloudWatch with debug, info, warn, and error levels
- ✅ **Lambda Function URLs**: Direct HTTP access without API Gateway
- ✅ **Manual Reset**: Support for manual reset via HTTP POST request
- ✅ **HTTP Basic Authentication**: Secure access with username/password protection

### Technical Features
- ✅ **Go 1.21**: Built with modern Go for high performance
- ✅ **ARM64 Architecture**: Uses ARM64 for better performance and cost efficiency
- ✅ **Amazon Linux Runtime**: Uses `provided.al2` runtime for Go applications
- ✅ **Unified Function**: Single Lambda function handles both HTTP and EventBridge events
- ✅ **AWS SDK v2**: Latest AWS SDK for Go with improved performance
- ✅ **Makefile Build System**: Automated cross-compilation for Amazon Linux ARM64
- ✅ **SAM Template**: Infrastructure as Code with AWS SAM
- ✅ **S3 State Storage**: Reliable state management with versioning
- ✅ **IAM Best Practices**: Least privilege access with specific permissions
- ✅ **Secure Authentication**: Constant-time credential comparison and proper security headers

## Architecture

```
┌─────────────────┐    ┌──────────────────────────────────┐    ┌─────────────────┐
│   Client        │    │  Unified Lambda Function         │    │  Security Group │
│   (Any IP)      │───▶│  • Function URL (HTTP + Auth)   │───▶│  (EC2)          │
└─────────────────┘    │  • EventBridge (Cron)           │    └─────────────────┘
                       │  • ARM64 Architecture            │
                       │  • Basic Authentication          │
                       └──────────────────────────────────┘
                                        │
                                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │  S3 Bucket       │    │  EventBridge    │
                       │  (State Storage) │    │  (Daily Reset)  │
                       └──────────────────┘    └─────────────────┘
```

## Project Structure

```
lambda-sg-authorizer/
├── cmd/
│   └── main/            # Unified Lambda function
│       └── main.go
├── pkg/
│   ├── auth/            # HTTP Basic Authentication
│   │   └── auth.go
│   ├── logger/          # Structured logging package
│   │   └── logger.go
│   ├── security/        # Security group management
│   │   └── security.go
│   └── state/           # S3 state management
│       └── state.go
├── internal/
│   └── config/          # Configuration management
│       └── config.go
├── bin/                 # Build output directory
├── template.yaml        # SAM template
├── Makefile            # Build automation
├── deploy.sh           # Deployment script
├── go.mod              # Go module dependencies
└── README.md           # This file
```

## Prerequisites

- **AWS CLI**: Configured with appropriate credentials
- **SAM CLI**: For deployment and testing
- **Go 1.21+**: For local development
- **Make**: For build automation
- **AWS Account**: With permissions to create Lambda, S3, EC2, and IAM resources

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd lambda-sg-authorizer
```

### 2. Initialize Go Module

```bash
make init
make deps
```

### 3. Build Application (ARM64)

```bash
make build
```

### 4. Deploy with SAM

```bash
# Using the deployment script (recommended)
./deploy.sh

# Or manually with SAM
make deploy
```

### 5. Configure Environment Variables

During deployment, you'll be prompted for:
- **SecurityGroupId**: The ID of the security group to manage (e.g., `sg-1234567890abcdef0`)
- **AccessPort**: TCP port to grant/revoke access for (e.g., `22` for SSH, `3306` for MySQL, `5432` for PostgreSQL)
- **S3BucketName**: Unique name for the state storage bucket (e.g., `my-sg-authorizer-state`)
- **BasicAuthUsername**: Username for HTTP Basic Authentication (default: `admin`)
- **BasicAuthPassword**: Password for HTTP Basic Authentication (minimum 8 characters)

## Usage

All HTTP requests to the Function URL require HTTP Basic Authentication.

### Grant Access

Make a GET request with Basic Authentication to grant your IP access on the configured port:

```bash
# Using curl with Basic Auth
curl -u admin:YourPassword123! https://your-function-url.lambda-url.region.on.aws/

# Using curl with Authorization header
curl -H "Authorization: Basic $(echo -n 'admin:YourPassword123!' | base64)" \
     https://your-function-url.lambda-url.region.on.aws/
```

Response:
```json
{
  "message": "Security group updated successfully. Access granted.",
  "success": true,
  "data": {
    "client_ip": "203.0.113.1",
    "username": "admin",
    "security_group_id": "sg-1234567890abcdef0",
    "port": 22,
    "action": "allow_access"
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Remove Access

Make a POST request with Basic Authentication and action `remove_access`:

```bash
curl -u admin:YourPassword123! \
  -X POST https://your-function-url.lambda-url.region.on.aws/ \
  -H "Content-Type: application/json" \
  -d '{"action": "remove_access"}'
```

### Check Access Status

Make a POST request with Basic Authentication and action `status`:

```bash
curl -u admin:YourPassword123! \
  -X POST https://your-function-url.lambda-url.region.on.aws/ \
  -H "Content-Type: application/json" \
  -d '{"action": "status"}'
```

### Manual Reset

Make a POST request with Basic Authentication and action `reset`:

```bash
curl -u admin:YourPassword123! \
  -X POST https://your-function-url.lambda-url.region.on.aws/ \
  -H "Content-Type: application/json" \
  -d '{"action": "reset"}'
```

Response:
```json
{
  "message": "Security group reset to original state successfully.",
  "success": true,
  "data": {
    "security_group_id": "sg-1234567890abcdef0",
    "rules_restored": 3,
    "username": "admin",
    "action": "reset"
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Authentication Errors

If authentication fails, you'll receive a 401 Unauthorized response:

```bash
curl https://your-function-url.lambda-url.region.on.aws/
```

Response:
```json
{
  "message": "Authorization header is required",
  "success": false,
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Configuration

### Environment Variables

The application uses the following environment variables:

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `SECURITY_GROUP_ID` | Security group ID to manage | Yes | - |
| `ACCESS_PORT` | TCP port to grant/revoke access for | No | 3306 |
| `S3_BUCKET_NAME` | S3 bucket for state storage | Yes | - |
| `BASIC_AUTH_USERNAME` | Username for HTTP Basic Auth | Yes | admin |
| `BASIC_AUTH_PASSWORD` | Password for HTTP Basic Auth | Yes | - |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARN, ERROR) | No | INFO |
| `AWS_REGION` | AWS region | No | us-east-1 |

### SAM Parameters

Configure these in `samconfig.toml` or during deployment:

```toml
[default.deploy.parameters]
stack_name = "sg-authorizer"
parameter_overrides = [
    "SecurityGroupId=sg-1234567890abcdef0",
    "AccessPort=22",
    "S3BucketName=my-sg-authorizer-state",
    "BasicAuthUsername=admin",
    "BasicAuthPassword=MySecurePassword123!"
]
```

## Security Considerations

### HTTP Basic Authentication

- **Username/Password Protection**: All Function URL endpoints require valid credentials
- **Constant-Time Comparison**: Credentials are validated using constant-time comparison to prevent timing attacks
- **Secure Headers**: Proper `WWW-Authenticate` header is sent with 401 responses
- **CORS Support**: Authentication header is included in CORS configuration
- **EventBridge Bypass**: EventBridge cron jobs bypass authentication (internal AWS traffic)

### Password Requirements

- Minimum 8 characters long
- Validated during deployment and configuration loading
- Stored as environment variables (consider using AWS Secrets Manager for production)

### IAM Permissions

The Lambda function has minimal required permissions:

**EC2 Permissions:**
- `ec2:DescribeSecurityGroups`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:RevokeSecurityGroupIngress`
- `ec2:DescribeSecurityGroupRules`

**S3 Permissions:**
- `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on bucket objects
- `s3:ListBucket` on the bucket

**CloudWatch Logs:**
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

### Function URL Security

- Function URLs are configured with `AuthType: NONE` but protected by application-level Basic Auth
- CORS is enabled for web browser access with `Authorization` header support
- All requests are logged with client IP and username for auditing
- Failed authentication attempts are logged for security monitoring

### State Management

- Original security group state is stored encrypted in S3
- S3 bucket has versioning enabled for state recovery
- Bucket access is restricted to the Lambda function only

## Development

### Building

```bash
# Build for production (Amazon Linux ARM64)
make build

# Build for development (local)
make build-dev

# Clean build artifacts
make clean
```

### Testing

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Lint code
make lint

# Format code
make fmt

# Run all checks
make check
```

### Local Development

```bash
# Start local API
make local-start

# Test unified function locally
make local-invoke

# Test reset functionality locally
make local-invoke-reset
```

### Authentication Testing

You can test authentication locally or create test credentials:

```go
// In Go code
authHeader := auth.CreateBasicAuthHeader("admin", "password123")
// Returns: "Basic YWRtaW46cGFzc3dvcmQxMjM="
```

```bash
# In shell
echo -n 'admin:password123' | base64
# Returns: YWRtaW46cGFzc3dvcmQxMjM=
```

## Deployment

### Using the Deployment Script

The recommended way to deploy is using the included deployment script:

```bash
./deploy.sh
```

This script will:
1. Check prerequisites
2. Clean and build the ARM64 binary
3. Validate the SAM template
4. Deploy with appropriate configuration
5. Display the Function URL and usage instructions

### Manual Deployment

```bash
# Validate template
make validate

# Deploy with guided setup
make deploy

# Quick deployment without prompts
make deploy-fast
```

### View Logs

```bash
# View function logs
make logs
```

## Event Handling

The unified Lambda function handles multiple event types:

### 1. Function URL Events (HTTP) - **Requires Authentication**
- **GET /**: Grant access for client IP on the configured port
- **POST /** with `{"action": "remove_access"}`: Remove access
- **POST /** with `{"action": "status"}`: Get status
- **POST /** with `{"action": "reset"}`: Manual reset
- **OPTIONS /**: CORS preflight (no authentication required)

### 2. EventBridge Events (Cron) - **No Authentication Required**
- Triggered every day at 2:00 AM UTC
- Automatically resets security group to original state

### 3. Direct Invocation - **No Authentication Required**
- Supports direct Lambda invocation for testing
- Defaults to reset operation for unknown event types

## ARM64 Benefits

The application uses ARM64 architecture which provides:

- **Better Performance**: Up to 19% better performance than x86_64
- **Cost Efficiency**: Up to 20% better price performance
- **Lower Energy**: More energy efficient
- **Modern Architecture**: Takes advantage of AWS Graviton2 processors

## Monitoring and Logging

### CloudWatch Logs

All actions are logged with structured JSON including:
- Request details (IP, method, headers)
- Authentication results (username, success/failure)
- Event type identification (Function URL vs EventBridge)
- AWS API calls (service, action, parameters)
- Error details with context
- Performance metrics (duration, status)

### Authentication Logs

Authentication events are specifically logged:
- `authentication_successful`: Valid credentials provided
- `authentication_failed`: Invalid credentials or missing auth
- `missing_authorization_header`: No Authorization header present
- `parse_basic_auth`: Issues parsing the Authorization header

### Log Levels

- **DEBUG**: Detailed execution flow and event type detection
- **INFO**: Important events and state changes
- **WARN**: Non-critical issues
- **ERROR**: Failures and exceptions

### Metrics

Monitor these CloudWatch metrics:
- Lambda invocation count and duration
- Error rates by event type
- Authentication success/failure rates
- S3 API call metrics
- EC2 API call metrics

## Troubleshooting

### Common Issues

1. **"Authorization header is required"**
   - Ensure you're sending the `Authorization` header with Basic auth
   - Use `-u username:password` with curl or set the header manually

2. **"Invalid username or password"**
   - Verify the username and password match your deployment configuration
   - Check that the password meets the 8-character minimum requirement

3. **"BASIC_AUTH_PASSWORD environment variable is required"**
   - Ensure the password parameter is set during deployment
   - Password must be at least 8 characters long

4. **"Could not determine client IP address"**
   - Check if requests are coming through a proxy/CDN
   - Verify X-Forwarded-For header is present

5. **"SECURITY_GROUP_ID environment variable is required"**
   - Ensure the security group ID is set in the SAM template
   - Redeploy with correct parameters

6. **"Failed to save original state"**
   - Check S3 bucket permissions
   - Verify bucket name is unique and accessible

7. **Build failures on ARM64**
   - Ensure Go 1.21+ is installed
   - Check `GOARCH=arm64` in Makefile

8. **EventBridge not triggering reset**
   - Check CloudWatch Events rules in AWS Console
   - Verify cron expression: `cron(0 2 * * ? *)`

### Debug Mode

Enable debug logging by setting `LOG_LEVEL=DEBUG`:

```bash
sam deploy --parameter-overrides "SecurityGroupId=sg-xxx AccessPort=22 S3BucketName=xxx-state BasicAuthPassword=MyPassword123! LOG_LEVEL=DEBUG"
```

### Testing Authentication

Test different authentication scenarios:

```bash
# Valid credentials
curl -u admin:YourPassword123! https://your-function-url/

# Invalid credentials
curl -u admin:wrongpassword https://your-function-url/

# Missing credentials
curl https://your-function-url/

# Manual header
curl -H "Authorization: Basic $(echo -n 'admin:YourPassword123!' | base64)" https://your-function-url/
```

## Reset Schedule

The reset function runs every day at 2:00 AM UTC via EventBridge:

```
Schedule: cron(0 2 * * ? *)
```

To modify the schedule, update the `Schedule` property in `template.yaml`:

```yaml
Events:
  DailyReset:
    Type: Schedule
    Properties:
      Schedule: cron(0 2 ? * SUN *)  # Sundays only, 2 AM UTC
```

## API Reference

### Authentication

All endpoints except OPTIONS require HTTP Basic Authentication:

```
Authorization: Basic <base64(username:password)>
```

### Endpoints

**Base URL:** `https://{function-url}.lambda-url.{region}.on.aws/`

#### GET /
**Authentication: Required**
Grant access to the client IP on the configured port.

#### POST /
**Authentication: Required**
Perform actions based on request body.

**Request Body:**
```json
{
  "action": "remove_access" | "status" | "reset" | "allow_access"
}
```

**Actions:**
- `allow_access`: Same as GET request (default)
- `remove_access`: Remove client IP from security group
- `status`: Get current access status
- `reset`: Manually reset to original state

#### OPTIONS /
**Authentication: Not Required**
CORS preflight response.

### Error Responses

#### 401 Unauthorized
```json
{
  "message": "Authorization header is required",
  "success": false,
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Performance Improvements

### ARM64 Architecture
- **Cold Start**: Faster cold starts compared to x86_64
- **Execution**: Better instruction efficiency
- **Memory**: More efficient memory usage

### Unified Function
- **Deployment**: Single deployment artifact
- **Maintenance**: Simplified codebase
- **Cost**: Reduced Lambda function count

### Authentication
- **Constant-Time**: Secure credential comparison
- **Minimal Overhead**: Efficient authentication processing
- **Bypass for Internal**: EventBridge events skip auth checks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes following Go conventions
4. Add tests for new functionality
5. Test authentication scenarios
6. Run `make check` to validate
7. Test on ARM64 architecture
8. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review CloudWatch logs for both event types and authentication events
3. Test locally using `make local-invoke` and `make local-invoke-reset`
4. Test authentication with different credential scenarios
5. Open an issue with logs and configuration details

---

**Note**: This application modifies AWS security groups and uses ARM64 architecture with HTTP Basic Authentication. Always test in a non-production environment first and ensure you have proper backups and monitoring in place. Store passwords securely and consider using AWS Secrets Manager for production deployments.
