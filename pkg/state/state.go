package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"lambda-sg-authorizer/pkg/logger"
)

const (
	StateFileName = "original-state.txt"
)

// SecurityGroupRule represents a security group rule
type SecurityGroupRule struct {
	Type        string   `json:"type"`     // "ingress" or "egress"
	Protocol    string   `json:"protocol"` // TCP, UDP, etc.
	FromPort    int32    `json:"from_port"`
	ToPort      int32    `json:"to_port"`
	CidrBlocks  []string `json:"cidr_blocks,omitempty"`
	GroupID     string   `json:"group_id,omitempty"`
	Description string   `json:"description,omitempty"`
}

// SecurityGroupState represents the original state of a security group
type SecurityGroupState struct {
	SecurityGroupID string              `json:"security_group_id"`
	Rules           []SecurityGroupRule `json:"rules"`
	Timestamp       string              `json:"timestamp"`
}

// StateManager handles security group state operations
type StateManager struct {
	s3Client   *s3.Client
	bucketName string
	logger     *logger.Logger
}

// NewStateManager creates a new state manager
func NewStateManager(s3Client *s3.Client, bucketName string, log *logger.Logger) *StateManager {
	return &StateManager{
		s3Client:   s3Client,
		bucketName: bucketName,
		logger:     log,
	}
}

// isS3NotFound returns true when err represents a missing S3 object (HTTP 404).
// HeadObject returns a generic HTTP error (no body to decode), so we check the
// status code as a fallback alongside the named SDK error types.
func isS3NotFound(err error) bool {
	var notFound *types.NotFound   // HeadObject 404
	var noSuchKey *types.NoSuchKey // GetObject 404
	if errors.As(err, &notFound) || errors.As(err, &noSuchKey) {
		return true
	}
	var httpErr *awshttp.ResponseError
	return errors.As(err, &httpErr) && httpErr.HTTPStatusCode() == 404
}

// SaveOriginalState saves the original security group state to S3
func (sm *StateManager) SaveOriginalState(ctx context.Context, state *SecurityGroupState) error {
	sm.logger.LogAction("save_original_state", map[string]interface{}{
		"security_group_id": state.SecurityGroupID,
		"bucket_name":       sm.bucketName,
		"rules_count":       len(state.Rules),
	})

	// Marshal state to JSON
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		sm.logger.LogError("marshal_state", err, map[string]interface{}{
			"security_group_id": state.SecurityGroupID,
		})
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Upload to S3
	_, err = sm.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(sm.bucketName),
		Key:         aws.String(StateFileName),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
		Metadata: map[string]string{
			"security-group-id": state.SecurityGroupID,
			"created-by":        "sg-authorizer",
		},
	})

	if err != nil {
		sm.logger.LogError("s3_put_object", err, map[string]interface{}{
			"bucket_name": sm.bucketName,
			"key":         StateFileName,
		})
		return fmt.Errorf("failed to save state to S3: %w", err)
	}

	sm.logger.LogAWSAction("s3", "put_object", map[string]interface{}{
		"bucket_name":       sm.bucketName,
		"key":               StateFileName,
		"security_group_id": state.SecurityGroupID,
	})

	return nil
}

// GetOriginalState retrieves the original security group state from S3
func (sm *StateManager) GetOriginalState(ctx context.Context) (*SecurityGroupState, error) {
	sm.logger.LogAction("get_original_state", map[string]interface{}{
		"bucket_name": sm.bucketName,
		"key":         StateFileName,
	})

	// Get object from S3
	result, err := sm.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(sm.bucketName),
		Key:    aws.String(StateFileName),
	})

	if err != nil {
		if isS3NotFound(err) {
			sm.logger.LogAction("state_file_not_found", map[string]interface{}{
				"bucket_name": sm.bucketName,
				"key":         StateFileName,
			})
			return nil, nil
		}

		sm.logger.LogError("s3_get_object", err, map[string]interface{}{
			"bucket_name": sm.bucketName,
			"key":         StateFileName,
		})
		return nil, fmt.Errorf("failed to get state from S3: %w", err)
	}

	defer result.Body.Close()

	// Read the content
	data, err := io.ReadAll(result.Body)
	if err != nil {
		sm.logger.LogError("read_s3_response", err, map[string]interface{}{
			"bucket_name": sm.bucketName,
			"key":         StateFileName,
		})
		return nil, fmt.Errorf("failed to read state data: %w", err)
	}

	// Unmarshal JSON
	var state SecurityGroupState
	if err := json.Unmarshal(data, &state); err != nil {
		sm.logger.LogError("unmarshal_state", err, map[string]interface{}{
			"bucket_name": sm.bucketName,
			"key":         StateFileName,
		})
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	sm.logger.LogAWSAction("s3", "get_object", map[string]interface{}{
		"bucket_name":       sm.bucketName,
		"key":               StateFileName,
		"security_group_id": state.SecurityGroupID,
		"rules_count":       len(state.Rules),
	})

	return &state, nil
}

// StateExists checks if the original state file exists in S3
func (sm *StateManager) StateExists(ctx context.Context) (bool, error) {
	sm.logger.LogAction("check_state_exists", map[string]interface{}{
		"bucket_name": sm.bucketName,
		"key":         StateFileName,
	})

	_, err := sm.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(sm.bucketName),
		Key:    aws.String(StateFileName),
	})

	if err != nil {
		if isS3NotFound(err) {
			sm.logger.LogAction("state_file_does_not_exist", map[string]interface{}{
				"bucket_name": sm.bucketName,
				"key":         StateFileName,
			})
			return false, nil
		}

		sm.logger.LogError("s3_head_object", err, map[string]interface{}{
			"bucket_name": sm.bucketName,
			"key":         StateFileName,
		})
		return false, fmt.Errorf("failed to check if state exists: %w", err)
	}

	sm.logger.LogAction("state_file_exists", map[string]interface{}{
		"bucket_name": sm.bucketName,
		"key":         StateFileName,
	})

	return true, nil
}

// DeleteState removes the state file from S3
func (sm *StateManager) DeleteState(ctx context.Context) error {
	sm.logger.LogAction("delete_state", map[string]interface{}{
		"bucket_name": sm.bucketName,
		"key":         StateFileName,
	})

	_, err := sm.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(sm.bucketName),
		Key:    aws.String(StateFileName),
	})

	if err != nil {
		sm.logger.LogError("s3_delete_object", err, map[string]interface{}{
			"bucket_name": sm.bucketName,
			"key":         StateFileName,
		})
		return fmt.Errorf("failed to delete state from S3: %w", err)
	}

	sm.logger.LogAWSAction("s3", "delete_object", map[string]interface{}{
		"bucket_name": sm.bucketName,
		"key":         StateFileName,
	})

	return nil
}
