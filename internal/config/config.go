package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds the application configuration
type Config struct {
	SecurityGroupID   string
	S3BucketName      string
	LogLevel          string
	AWSRegion         string
	BasicAuthUsername string
	BasicAuthPassword string
	AccessPort        int32
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	port, err := parsePort(os.Getenv("ACCESS_PORT"))
	if err != nil {
		return nil, fmt.Errorf("invalid ACCESS_PORT: %w", err)
	}

	cfg := &Config{
		SecurityGroupID:   os.Getenv("SECURITY_GROUP_ID"),
		S3BucketName:      os.Getenv("S3_BUCKET_NAME"),
		LogLevel:          os.Getenv("LOG_LEVEL"),
		AWSRegion:         os.Getenv("AWS_REGION"),
		BasicAuthUsername: os.Getenv("BASIC_AUTH_USERNAME"),
		BasicAuthPassword: os.Getenv("BASIC_AUTH_PASSWORD"),
		AccessPort:        port,
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}

	if cfg.AWSRegion == "" {
		cfg.AWSRegion = "us-east-1"
	}

	if cfg.BasicAuthUsername == "" {
		cfg.BasicAuthUsername = "admin"
	}

	return cfg, nil
}

// parsePort parses and validates a port number string.
// Defaults to 3306 when portStr is empty.
func parsePort(portStr string) (int32, error) {
	if portStr == "" {
		return 3306, nil
	}
	port, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("must be a valid integer: %w", err)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("must be between 1 and 65535, got %d", port)
	}
	return int32(port), nil
}

// validate checks if all required configuration is present
func (c *Config) validate() error {
	if c.SecurityGroupID == "" {
		return fmt.Errorf("SECURITY_GROUP_ID environment variable is required")
	}

	if c.S3BucketName == "" {
		return fmt.Errorf("S3_BUCKET_NAME environment variable is required")
	}

	if c.BasicAuthPassword == "" {
		return fmt.Errorf("BASIC_AUTH_PASSWORD environment variable is required")
	}

	if len(c.BasicAuthPassword) < 8 {
		return fmt.Errorf("BASIC_AUTH_PASSWORD must be at least 8 characters long")
	}

	return nil
}

// GetSecurityGroupID returns the security group ID
func (c *Config) GetSecurityGroupID() string {
	return c.SecurityGroupID
}

// GetS3BucketName returns the S3 bucket name
func (c *Config) GetS3BucketName() string {
	return c.S3BucketName
}

// GetLogLevel returns the log level
func (c *Config) GetLogLevel() string {
	return c.LogLevel
}

// GetAWSRegion returns the AWS region
func (c *Config) GetAWSRegion() string {
	return c.AWSRegion
}

// GetBasicAuthUsername returns the basic auth username
func (c *Config) GetBasicAuthUsername() string {
	return c.BasicAuthUsername
}

// GetBasicAuthPassword returns the basic auth password
func (c *Config) GetBasicAuthPassword() string {
	return c.BasicAuthPassword
}

// GetAccessPort returns the port to grant/revoke access for
func (c *Config) GetAccessPort() int32 {
	return c.AccessPort
}
