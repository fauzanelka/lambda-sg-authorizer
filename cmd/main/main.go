package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	appConfig "lambda-sg-authorizer/internal/config"
	"lambda-sg-authorizer/pkg/auth"
	"lambda-sg-authorizer/pkg/logger"
	"lambda-sg-authorizer/pkg/security"
	"lambda-sg-authorizer/pkg/state"
)

// UnifiedResponse represents the unified Lambda response for both HTTP and EventBridge
type UnifiedResponse struct {
	// HTTP response fields
	StatusCode int               `json:"statusCode,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`

	// EventBridge response fields
	Message         string `json:"message,omitempty"`
	Success         bool   `json:"success"`
	SecurityGroupID string `json:"security_group_id,omitempty"`
	RulesRestored   int    `json:"rules_restored,omitempty"`
	Timestamp       string `json:"timestamp"`

	// Common fields
	Source string `json:"source"` // "function_url" or "eventbridge"
}

// RequestBody represents the JSON request body for HTTP requests
type RequestBody struct {
	Action string `json:"action,omitempty"`
}

// HTTPResponseBody represents the JSON response body for HTTP requests
type HTTPResponseBody struct {
	Message   string      `json:"message"`
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// EventBridgeEvent represents custom EventBridge event payload
type EventBridgeEvent struct {
	Source string `json:"source"`
	Action string `json:"action"`
}

var (
	log           *logger.Logger
	cfg           *appConfig.Config
	sgManager     *security.SecurityGroupManager
	stateManager  *state.StateManager
	authenticator *auth.Authenticator
	ec2Client     *ec2.Client
	s3Client      *s3.Client
)

func init() {
	var err error

	log = logger.New()
	log.Info("Initializing Security Group Authorizer")

	cfg, err = appConfig.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.LogAction("configuration_loaded", map[string]interface{}{
		"security_group_id": cfg.GetSecurityGroupID(),
		"s3_bucket":         cfg.GetS3BucketName(),
		"log_level":         cfg.GetLogLevel(),
		"aws_region":        cfg.GetAWSRegion(),
		"auth_username":     cfg.GetBasicAuthUsername(),
		"auth_enabled":      cfg.GetBasicAuthPassword() != "",
		"access_port":       cfg.GetAccessPort(),
	})

	awsCfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Failed to load AWS configuration: %v", err)
	}

	ec2Client = ec2.NewFromConfig(awsCfg)
	s3Client = s3.NewFromConfig(awsCfg)

	sgManager = security.NewSecurityGroupManager(ec2Client, log)
	stateManager = state.NewStateManager(s3Client, cfg.GetS3BucketName(), log)
	authenticator = auth.NewAuthenticator(cfg.GetBasicAuthUsername(), cfg.GetBasicAuthPassword(), log)

	log.Info("Security Group Authorizer initialization completed successfully")
}

// handleRequest is the main entry point that routes requests based on event type
func handleRequest(ctx context.Context, event interface{}) (interface{}, error) {
	startTime := time.Now()

	log.LogAction("lambda_invocation", map[string]interface{}{
		"event_type": fmt.Sprintf("%T", event),
	})

	switch evt := event.(type) {
	case events.LambdaFunctionURLRequest:
		// Function URL request (HTTP) - requires authentication
		response, err := handleFunctionURLRequest(ctx, evt)
		log.LogAction("function_url_request_completed", map[string]interface{}{
			"duration":    time.Since(startTime).String(),
			"status_code": response.StatusCode,
		})
		return response, err

	case events.CloudWatchEvent:
		// EventBridge (CloudWatch Events) request - no authentication required
		response, err := handleEventBridgeRequest(ctx, evt)
		log.LogAction("eventbridge_request_completed", map[string]interface{}{
			"duration": time.Since(startTime).String(),
			"success":  response.Success,
		})
		return response, err

	case map[string]interface{}:
		// Check if this is a Function URL request based on its structure
		if isLambdaFunctionURLRequest(evt) {
			// Convert map to LambdaFunctionURLRequest
			eventBytes, _ := json.Marshal(evt)
			var urlRequest events.LambdaFunctionURLRequest
			if err := json.Unmarshal(eventBytes, &urlRequest); err != nil {
				log.LogError("parse_function_url_request", err, map[string]interface{}{
					"event_keys": getMapKeys(evt),
				})
				return createHTTPErrorResponse(http.StatusInternalServerError, "Failed to parse Function URL request"), nil
			}

			log.LogAction("function_url_request_detected_from_map", map[string]interface{}{
				"method": urlRequest.RequestContext.HTTP.Method,
				"path":   urlRequest.RequestContext.HTTP.Path,
			})

			response, err := handleFunctionURLRequest(ctx, urlRequest)
			log.LogAction("function_url_request_completed", map[string]interface{}{
				"duration":    time.Since(startTime).String(),
				"status_code": response.StatusCode,
			})
			return response, err
		}

		// Generic event (could be EventBridge with different structure)
		if source, exists := evt["source"]; exists && source == "eventbridge" {
			// Convert to EventBridge event
			eventBytes, _ := json.Marshal(evt)
			var ebEvent EventBridgeEvent
			json.Unmarshal(eventBytes, &ebEvent)
			return handleDirectEventBridge(ctx, ebEvent)
		}
		// Fallback: handle as unknown event
		return handleUnknownEvent(ctx, evt)

	case json.RawMessage:
		// Direct invocation with JSON payload
		return handleRawMessage(ctx, evt)

	default:
		log.LogAction("unknown_event_type", map[string]interface{}{
			"event_type": fmt.Sprintf("%T", event),
		})
		return createEventBridgeResponse(false, "Unknown event type", 0), nil
	}
}

// handleFunctionURLRequest handles HTTP requests from Function URL with authentication
func handleFunctionURLRequest(ctx context.Context, request events.LambdaFunctionURLRequest) (UnifiedResponse, error) {
	startTime := time.Now()

	log.LogAction("function_url_request_started", map[string]interface{}{
		"method":       request.RequestContext.HTTP.Method,
		"path":         request.RequestContext.HTTP.Path,
		"user_agent":   request.Headers["user-agent"],
		"content_type": request.Headers["content-type"],
	})

	// Handle CORS preflight requests without authentication
	if request.RequestContext.HTTP.Method == "OPTIONS" {
		return createCORSResponse(), nil
	}

	// Authenticate request
	authResult := authenticator.ValidateBasicAuth(request.Headers)
	if !authResult.IsAuthenticated {
		log.LogAction("authentication_failed", map[string]interface{}{
			"method":   request.RequestContext.HTTP.Method,
			"path":     request.RequestContext.HTTP.Path,
			"error":    authResult.ErrorMessage,
			"duration": time.Since(startTime).String(),
		})
		return createUnauthorizedResponse(authResult.ErrorMessage), nil
	}

	log.LogAction("authentication_successful", map[string]interface{}{
		"username": authResult.Username,
		"method":   request.RequestContext.HTTP.Method,
		"path":     request.RequestContext.HTTP.Path,
	})

	// Extract client IP from headers
	clientIP := sgManager.GetClientIP(request.Headers)
	if clientIP == "" {
		log.LogError("extract_client_ip", fmt.Errorf("could not determine client IP address"), map[string]interface{}{
			"headers":  request.Headers,
			"duration": time.Since(startTime).String(),
			"username": authResult.Username,
		})
		return createHTTPErrorResponse(http.StatusBadRequest, "Could not determine client IP address"), nil
	}

	log.LogHTTPRequest(request.RequestContext.HTTP.Method, request.RequestContext.HTTP.Path, clientIP, http.StatusOK)

	var response UnifiedResponse
	var err error

	// Handle different HTTP methods
	switch request.RequestContext.HTTP.Method {
	case "GET":
		response, err = handleGetRequest(ctx, clientIP, authResult.Username)
	case "POST":
		response, err = handlePostRequest(ctx, request, clientIP, authResult.Username)
	default:
		response, err = createHTTPErrorResponse(http.StatusMethodNotAllowed, "Method not allowed"), nil
	}

	log.LogAction("function_url_request_completed", map[string]interface{}{
		"client_ip":   clientIP,
		"username":    authResult.Username,
		"status_code": response.StatusCode,
		"duration":    time.Since(startTime).String(),
		"method":      request.RequestContext.HTTP.Method,
	})

	return response, err
}

// handleEventBridgeRequest handles EventBridge cron job events
func handleEventBridgeRequest(ctx context.Context, event events.CloudWatchEvent) (UnifiedResponse, error) {
	startTime := time.Now()

	log.LogAction("eventbridge_request_started", map[string]interface{}{
		"event_source": event.Source,
		"event_time":   event.Time,
		"resources":    event.Resources,
	})

	// Parse the event detail
	var eventDetail EventBridgeEvent
	if event.Detail != nil {
		if err := json.Unmarshal(event.Detail, &eventDetail); err != nil {
			log.LogError("parse_event_detail", err, map[string]interface{}{
				"event_detail": string(event.Detail),
			})
			// Continue with default reset action
			eventDetail.Action = "reset"
		}
	} else {
		// Default to reset action
		eventDetail.Action = "reset"
	}

	// Perform the reset operation
	response, err := performReset(ctx)
	if err != nil {
		log.LogError("perform_reset", err, map[string]interface{}{
			"security_group_id": cfg.GetSecurityGroupID(),
			"duration":          time.Since(startTime).String(),
		})
		return createEventBridgeResponse(false, fmt.Sprintf("Reset failed: %v", err), 0), nil
	}

	log.LogAction("eventbridge_request_completed", map[string]interface{}{
		"security_group_id": cfg.GetSecurityGroupID(),
		"duration":          time.Since(startTime).String(),
		"rules_restored":    response.RulesRestored,
	})

	return response, nil
}

// handleDirectEventBridge handles direct EventBridge events
func handleDirectEventBridge(ctx context.Context, event EventBridgeEvent) (UnifiedResponse, error) {
	log.LogAction("direct_eventbridge_request", map[string]interface{}{
		"source": event.Source,
		"action": event.Action,
	})

	return performReset(ctx)
}

// handleRawMessage handles raw JSON message events
func handleRawMessage(ctx context.Context, payload json.RawMessage) (UnifiedResponse, error) {
	log.LogAction("raw_message_received", map[string]interface{}{
		"payload_size": len(payload),
	})

	// Try to parse as EventBridge event
	var eventDetail EventBridgeEvent
	if err := json.Unmarshal(payload, &eventDetail); err == nil && eventDetail.Source == "eventbridge" {
		return handleDirectEventBridge(ctx, eventDetail)
	}

	// Default to reset operation for raw messages
	return performReset(ctx)
}

// handleUnknownEvent handles unknown event types
func handleUnknownEvent(ctx context.Context, event map[string]interface{}) (UnifiedResponse, error) {
	log.LogAction("unknown_event_received", map[string]interface{}{
		"event_keys": getMapKeys(event),
	})

	// Default to reset operation
	return performReset(ctx)
}

// handleGetRequest handles GET requests to grant access
func handleGetRequest(ctx context.Context, clientIP, username string) (UnifiedResponse, error) {
	log.LogAction("handle_get_request", map[string]interface{}{
		"client_ip": clientIP,
		"username":  username,
	})

	// Check if original state exists
	exists, err := stateManager.StateExists(ctx)
	if err != nil {
		log.LogError("check_state_exists", err, map[string]interface{}{
			"client_ip": clientIP,
			"username":  username,
		})
		return createHTTPErrorResponse(http.StatusInternalServerError, "Failed to check state"), nil
	}

	if !exists {
		log.LogAction("first_time_setup", map[string]interface{}{
			"client_ip":         clientIP,
			"username":          username,
			"security_group_id": cfg.GetSecurityGroupID(),
		})

		// First time - save original state
		if err := saveOriginalState(ctx); err != nil {
			log.LogError("save_original_state", err, map[string]interface{}{
				"client_ip":         clientIP,
				"username":          username,
				"security_group_id": cfg.GetSecurityGroupID(),
			})
			return createHTTPErrorResponse(http.StatusInternalServerError, "Failed to save original state"), nil
		}
	}

	// Add ingress rule for client IP
	if err := sgManager.AddIngressRule(ctx, cfg.GetSecurityGroupID(), clientIP, cfg.GetAccessPort()); err != nil {
		log.LogError("add_ingress_rule", err, map[string]interface{}{
			"client_ip":         clientIP,
			"username":          username,
			"security_group_id": cfg.GetSecurityGroupID(),
		})
		return createHTTPErrorResponse(http.StatusInternalServerError, "Failed to update security group"), nil
	}

	responseData := map[string]interface{}{
		"client_ip":         clientIP,
		"username":          username,
		"security_group_id": cfg.GetSecurityGroupID(),
		"port":              cfg.GetAccessPort(),
		"action":            "allow_access",
	}

	return createHTTPSuccessResponse("Security group updated successfully. Access granted.", responseData), nil
}

// handlePostRequest handles POST requests with actions
func handlePostRequest(ctx context.Context, request events.LambdaFunctionURLRequest, clientIP, username string) (UnifiedResponse, error) {
	log.LogAction("handle_post_request", map[string]interface{}{
		"client_ip": clientIP,
		"username":  username,
		"body_size": len(request.Body),
	})

	// Parse request body
	var reqBody RequestBody
	if request.Body != "" {
		if err := json.Unmarshal([]byte(request.Body), &reqBody); err != nil {
			log.LogError("parse_request_body", err, map[string]interface{}{
				"client_ip": clientIP,
				"username":  username,
				"body":      request.Body,
			})
			return createHTTPErrorResponse(http.StatusBadRequest, "Invalid JSON in request body"), nil
		}
	}

	// Handle different actions
	switch reqBody.Action {
	case "remove_access":
		return handleRemoveAccess(ctx, clientIP, username)
	case "status":
		return handleStatusRequest(ctx, clientIP, username)
	case "reset":
		// Allow manual reset via POST request
		resetResponse, err := performReset(ctx)
		if err != nil {
			return createHTTPErrorResponse(http.StatusInternalServerError, "Failed to reset security group"), nil
		}

		responseData := map[string]interface{}{
			"security_group_id": cfg.GetSecurityGroupID(),
			"rules_restored":    resetResponse.RulesRestored,
			"username":          username,
			"action":            "reset",
		}
		return createHTTPSuccessResponse("Security group reset to original state successfully.", responseData), nil
	default:
		// Default action is to grant access (same as GET)
		return handleGetRequest(ctx, clientIP, username)
	}
}

// handleRemoveAccess removes access for the client IP
func handleRemoveAccess(ctx context.Context, clientIP, username string) (UnifiedResponse, error) {
	log.LogAction("handle_remove_access", map[string]interface{}{
		"client_ip": clientIP,
		"username":  username,
	})

	// Remove ingress rule for client IP
	if err := sgManager.RemoveIngressRuleForIP(ctx, cfg.GetSecurityGroupID(), clientIP, cfg.GetAccessPort()); err != nil {
		log.LogError("remove_ingress_rule", err, map[string]interface{}{
			"client_ip":         clientIP,
			"username":          username,
			"security_group_id": cfg.GetSecurityGroupID(),
		})
		return createHTTPErrorResponse(http.StatusInternalServerError, "Failed to remove access"), nil
	}

	responseData := map[string]interface{}{
		"client_ip":         clientIP,
		"username":          username,
		"security_group_id": cfg.GetSecurityGroupID(),
		"port":              cfg.GetAccessPort(),
		"action":            "remove_access",
	}

	return createHTTPSuccessResponse("Access removed successfully.", responseData), nil
}

// handleStatusRequest returns the current status
func handleStatusRequest(ctx context.Context, clientIP, username string) (UnifiedResponse, error) {
	log.LogAction("handle_status_request", map[string]interface{}{
		"client_ip": clientIP,
		"username":  username,
	})

	// Get current security group rules
	rules, err := sgManager.GetSecurityGroupRules(ctx, cfg.GetSecurityGroupID())
	if err != nil {
		log.LogError("get_security_group_rules", err, map[string]interface{}{
			"client_ip":         clientIP,
			"username":          username,
			"security_group_id": cfg.GetSecurityGroupID(),
		})
		return createHTTPErrorResponse(http.StatusInternalServerError, "Failed to get security group status"), nil
	}

	// Check if client IP has access on the configured port
	hasAccess := false
	clientCIDR := fmt.Sprintf("%s/32", clientIP)
	accessPort := cfg.GetAccessPort()
	for _, rule := range rules {
		if rule.Type == "ingress" && rule.FromPort == accessPort && rule.ToPort == accessPort {
			for _, cidr := range rule.CidrBlocks {
				if cidr == clientCIDR {
					hasAccess = true
					break
				}
			}
		}
		if hasAccess {
			break
		}
	}

	// Check if original state exists
	exists, err := stateManager.StateExists(ctx)
	if err != nil {
		log.LogError("check_state_exists", err, map[string]interface{}{
			"client_ip": clientIP,
			"username":  username,
		})
		return createHTTPErrorResponse(http.StatusInternalServerError, "Failed to check state"), nil
	}

	responseData := map[string]interface{}{
		"client_ip":             clientIP,
		"username":              username,
		"security_group_id":     cfg.GetSecurityGroupID(),
		"has_access":            hasAccess,
		"port":                  accessPort,
		"original_state_exists": exists,
		"total_rules":           len(rules),
	}

	return createHTTPSuccessResponse("Security group status retrieved successfully.", responseData), nil
}

// performReset resets the security group to its original state
func performReset(ctx context.Context) (UnifiedResponse, error) {
	log.LogAction("reset_operation_started", map[string]interface{}{
		"security_group_id": cfg.GetSecurityGroupID(),
	})

	// Check if original state exists
	exists, err := stateManager.StateExists(ctx)
	if err != nil {
		return createEventBridgeResponse(false, fmt.Sprintf("Failed to check if original state exists: %v", err), 0), fmt.Errorf("failed to check if original state exists: %w", err)
	}

	if !exists {
		log.LogAction("no_original_state_found", map[string]interface{}{
			"security_group_id": cfg.GetSecurityGroupID(),
		})
		return createEventBridgeResponse(true, "No original state found. Nothing to reset.", 0), nil
	}

	// Get original state
	originalState, err := stateManager.GetOriginalState(ctx)
	if err != nil {
		return createEventBridgeResponse(false, fmt.Sprintf("Failed to get original state: %v", err), 0), fmt.Errorf("failed to get original state: %w", err)
	}

	if originalState == nil {
		log.LogAction("original_state_is_null", map[string]interface{}{
			"security_group_id": cfg.GetSecurityGroupID(),
		})
		return createEventBridgeResponse(true, "Original state is empty. Nothing to reset.", 0), nil
	}

	log.LogAction("original_state_retrieved", map[string]interface{}{
		"security_group_id":    originalState.SecurityGroupID,
		"original_rules_count": len(originalState.Rules),
		"original_timestamp":   originalState.Timestamp,
	})

	// Restore original rules
	if err := sgManager.RestoreOriginalRules(ctx, cfg.GetSecurityGroupID(), originalState); err != nil {
		return createEventBridgeResponse(false, fmt.Sprintf("Failed to restore original rules: %v", err), 0), fmt.Errorf("failed to restore original rules: %w", err)
	}

	log.LogAction("security_group_restored", map[string]interface{}{
		"security_group_id": cfg.GetSecurityGroupID(),
		"rules_count":       len(originalState.Rules),
	})

	return createEventBridgeResponse(true, "Security group successfully restored to original state", len(originalState.Rules)), nil
}

// saveOriginalState saves the current state as the original state
func saveOriginalState(ctx context.Context) error {
	log.LogAction("save_original_state_start", map[string]interface{}{
		"security_group_id": cfg.GetSecurityGroupID(),
	})

	// Get current security group rules
	rules, err := sgManager.GetSecurityGroupRules(ctx, cfg.GetSecurityGroupID())
	if err != nil {
		return fmt.Errorf("failed to get security group rules: %w", err)
	}

	// Create state object
	originalState := &state.SecurityGroupState{
		SecurityGroupID: cfg.GetSecurityGroupID(),
		Rules:           rules,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}

	// Save to S3
	if err := stateManager.SaveOriginalState(ctx, originalState); err != nil {
		return fmt.Errorf("failed to save original state: %w", err)
	}

	log.LogAction("save_original_state_completed", map[string]interface{}{
		"security_group_id": cfg.GetSecurityGroupID(),
		"rules_count":       len(rules),
		"timestamp":         originalState.Timestamp,
	})

	return nil
}

// createHTTPSuccessResponse creates a successful HTTP response
func createHTTPSuccessResponse(message string, data interface{}) UnifiedResponse {
	body := HTTPResponseBody{
		Message:   message,
		Success:   true,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	bodyJSON, _ := json.Marshal(body)

	return UnifiedResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:      string(bodyJSON),
		Source:    "function_url",
		Success:   true,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// createHTTPErrorResponse creates an error HTTP response
func createHTTPErrorResponse(statusCode int, message string) UnifiedResponse {
	body := HTTPResponseBody{
		Message:   message,
		Success:   false,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	bodyJSON, _ := json.Marshal(body)

	return UnifiedResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
		Body:      string(bodyJSON),
		Source:    "function_url",
		Success:   false,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// createUnauthorizedResponse creates a 401 Unauthorized response
func createUnauthorizedResponse(message string) UnifiedResponse {
	body := HTTPResponseBody{
		Message:   message,
		Success:   false,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	bodyJSON, _ := json.Marshal(body)

	return UnifiedResponse{
		StatusCode: http.StatusUnauthorized,
		Headers: map[string]string{
			"Content-Type":                 "application/json",
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
			"WWW-Authenticate":             "Basic realm=\"Security Group Authorizer\"",
		},
		Body:      string(bodyJSON),
		Source:    "function_url",
		Success:   false,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// createCORSResponse creates a CORS preflight response
func createCORSResponse() UnifiedResponse {
	return UnifiedResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
			"Access-Control-Max-Age":       "86400",
		},
		Body:      "",
		Source:    "function_url",
		Success:   true,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// createEventBridgeResponse creates an EventBridge response
func createEventBridgeResponse(success bool, message string, rulesRestored int) UnifiedResponse {
	return UnifiedResponse{
		Message:         message,
		Success:         success,
		SecurityGroupID: cfg.GetSecurityGroupID(),
		RulesRestored:   rulesRestored,
		Source:          "eventbridge",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}
}

// getMapKeys returns all keys of a map
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// isLambdaFunctionURLRequest checks if a map[string]interface{} represents a Lambda Function URL request
// by checking for the presence of specific keys that are unique to Function URL requests
func isLambdaFunctionURLRequest(event map[string]interface{}) bool {
	// Check for required Function URL request fields
	requiredKeys := []string{"requestContext", "headers", "version"}
	functionURLKeys := []string{"rawPath", "rawQueryString", "routeKey"}

	// Check if all required keys exist
	for _, key := range requiredKeys {
		if _, exists := event[key]; !exists {
			return false
		}
	}

	// Check if at least some Function URL specific keys exist
	functionURLKeyCount := 0
	for _, key := range functionURLKeys {
		if _, exists := event[key]; exists {
			functionURLKeyCount++
		}
	}

	// Must have at least 2 of the Function URL specific keys
	if functionURLKeyCount < 2 {
		return false
	}

	// Additional check: requestContext should have HTTP field for Function URL
	if requestContext, ok := event["requestContext"].(map[string]interface{}); ok {
		if _, hasHTTP := requestContext["http"]; hasHTTP {
			return true
		}
		// Check for capital HTTP (some versions use different casing)
		if _, hasHTTP := requestContext["HTTP"]; hasHTTP {
			return true
		}
	}

	return false
}

func main() {
	lambda.Start(handleRequest)
}
