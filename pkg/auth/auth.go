package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"lambda-sg-authorizer/pkg/logger"
)

// Authenticator handles HTTP Basic Authentication
type Authenticator struct {
	username string
	password string
	logger   *logger.Logger
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(username, password string, log *logger.Logger) *Authenticator {
	return &Authenticator{
		username: username,
		password: password,
		logger:   log,
	}
}

// AuthResult represents the result of authentication
type AuthResult struct {
	IsAuthenticated bool
	Username        string
	ErrorMessage    string
}

// ValidateBasicAuth validates HTTP Basic Authentication from headers
func (a *Authenticator) ValidateBasicAuth(headers map[string]string) AuthResult {
	a.logger.LogAction("validate_basic_auth", map[string]interface{}{
		"headers_present": len(headers),
	})

	// Check for Authorization header
	authHeader := getAuthorizationHeader(headers)
	if authHeader == "" {
		a.logger.LogAction("missing_authorization_header", map[string]interface{}{
			"available_headers": getHeaderKeys(headers),
		})
		return AuthResult{
			IsAuthenticated: false,
			ErrorMessage:    "Authorization header is required",
		}
	}

	// Parse Basic Auth
	username, password, err := parseBasicAuth(authHeader)
	if err != nil {
		a.logger.LogError("parse_basic_auth", err, map[string]interface{}{
			"auth_header_prefix": truncateString(authHeader, 20),
		})
		return AuthResult{
			IsAuthenticated: false,
			ErrorMessage:    "Invalid Authorization header format",
		}
	}

	// Validate credentials using constant-time comparison
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(a.password)) == 1

	if usernameMatch && passwordMatch {
		a.logger.LogAction("authentication_successful", map[string]interface{}{
			"username": username,
		})
		return AuthResult{
			IsAuthenticated: true,
			Username:        username,
		}
	}

	a.logger.LogAction("authentication_failed", map[string]interface{}{
		"username":        username,
		"username_match":  usernameMatch,
		"password_length": len(password),
	})

	return AuthResult{
		IsAuthenticated: false,
		ErrorMessage:    "Invalid username or password",
	}
}

// getAuthorizationHeader retrieves the Authorization header (case-insensitive)
func getAuthorizationHeader(headers map[string]string) string {
	// Check common case variations
	authHeaders := []string{
		"Authorization",
		"authorization",
		"AUTHORIZATION",
		"x-authorization",
		"X-Authorization",
	}

	for _, headerName := range authHeaders {
		if value, exists := headers[headerName]; exists && value != "" {
			return value
		}
	}

	return ""
}

// parseBasicAuth parses the Basic Authentication header
func parseBasicAuth(authHeader string) (username, password string, err error) {
	// Check if it starts with "Basic "
	const basicPrefix = "Basic "
	if !strings.HasPrefix(authHeader, basicPrefix) {
		return "", "", fmt.Errorf("authorization header must start with 'Basic '")
	}

	// Extract the base64 encoded credentials
	encoded := authHeader[len(basicPrefix):]
	if encoded == "" {
		return "", "", fmt.Errorf("missing credentials in authorization header")
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 encoding: %w", err)
	}

	// Split username:password
	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("credentials must be in format 'username:password'")
	}

	return parts[0], parts[1], nil
}

// CreateBasicAuthHeader creates a Basic Auth header for testing/client use
func CreateBasicAuthHeader(username, password string) string {
	credentials := fmt.Sprintf("%s:%s", username, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	return fmt.Sprintf("Basic %s", encoded)
}

// Helper functions
func getHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	return keys
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
