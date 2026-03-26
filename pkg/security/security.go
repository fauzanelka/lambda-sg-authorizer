package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"lambda-sg-authorizer/pkg/logger"
	"lambda-sg-authorizer/pkg/state"
)

// SecurityGroupManager handles security group operations
type SecurityGroupManager struct {
	ec2Client *ec2.Client
	logger    *logger.Logger
}

// NewSecurityGroupManager creates a new security group manager
func NewSecurityGroupManager(ec2Client *ec2.Client, log *logger.Logger) *SecurityGroupManager {
	return &SecurityGroupManager{
		ec2Client: ec2Client,
		logger:    log,
	}
}

// GetClientIP extracts the real client IP from Lambda Function URL request
func (sgm *SecurityGroupManager) GetClientIP(headers map[string]string) string {
	sgm.logger.LogAction("extract_client_ip", map[string]interface{}{
		"headers_count": len(headers),
	})

	// Check various headers that might contain the real client IP
	ipHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Client-IP",
		"CF-Connecting-IP", // Cloudflare
		"True-Client-IP",   // Cloudflare Enterprise
		"x-forwarded-for",
		"x-real-ip",
		"x-client-ip",
		"cf-connecting-ip",
		"true-client-ip",
	}

	for _, header := range ipHeaders {
		if ip := headers[header]; ip != "" {
			sgm.logger.LogAction("found_ip_in_header", map[string]interface{}{
				"header": header,
				"ip":     ip,
			})

			// X-Forwarded-For can contain multiple IPs, take the first one
			if header == "X-Forwarded-For" {
				ips := strings.Split(ip, ",")
				if len(ips) > 0 {
					ip = strings.TrimSpace(ips[0])
				}
			}

			// Validate IP address
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				sgm.logger.LogAction("validated_client_ip", map[string]interface{}{
					"client_ip": ip,
					"header":    header,
				})
				return ip
			}
		}
	}

	// Fallback: check if there's a source IP in the request context
	// This would be available in the Lambda event
	sgm.logger.LogAction("no_client_ip_found", map[string]interface{}{
		"available_headers": getHeaderKeys(headers),
	})

	return ""
}

// GetClientIPFromRequest extracts client IP from HTTP request
func (sgm *SecurityGroupManager) GetClientIPFromRequest(r *http.Request) string {
	// Convert http.Header to map[string]string
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return sgm.GetClientIP(headers)
}

// GetSecurityGroupRules retrieves all rules for a security group
func (sgm *SecurityGroupManager) GetSecurityGroupRules(ctx context.Context, groupID string) ([]state.SecurityGroupRule, error) {
	sgm.logger.LogAction("get_security_group_rules", map[string]interface{}{
		"security_group_id": groupID,
	})

	// Describe security group
	result, err := sgm.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{groupID},
	})

	if err != nil {
		sgm.logger.LogError("describe_security_groups", err, map[string]interface{}{
			"security_group_id": groupID,
		})
		return nil, fmt.Errorf("failed to describe security group: %w", err)
	}

	if len(result.SecurityGroups) == 0 {
		return nil, fmt.Errorf("security group %s not found", groupID)
	}

	sg := result.SecurityGroups[0]
	var rules []state.SecurityGroupRule

	// Process ingress rules
	for _, rule := range sg.IpPermissions {
		rules = append(rules, sgm.convertIngressRule(rule)...)
	}

	// Process egress rules
	for _, rule := range sg.IpPermissionsEgress {
		rules = append(rules, sgm.convertEgressRule(rule)...)
	}

	sgm.logger.LogAWSAction("ec2", "describe_security_groups", map[string]interface{}{
		"security_group_id": groupID,
		"rules_count":       len(rules),
		"ingress_rules":     len(sg.IpPermissions),
		"egress_rules":      len(sg.IpPermissionsEgress),
	})

	return rules, nil
}

// convertIngressRule converts EC2 ingress rule to our format
func (sgm *SecurityGroupManager) convertIngressRule(rule types.IpPermission) []state.SecurityGroupRule {
	var rules []state.SecurityGroupRule

	protocol := aws.ToString(rule.IpProtocol)
	fromPort := aws.ToInt32(rule.FromPort)
	toPort := aws.ToInt32(rule.ToPort)

	// Handle CIDR blocks
	for _, cidr := range rule.IpRanges {
		rules = append(rules, state.SecurityGroupRule{
			Type:        "ingress",
			Protocol:    protocol,
			FromPort:    fromPort,
			ToPort:      toPort,
			CidrBlocks:  []string{aws.ToString(cidr.CidrIp)},
			Description: aws.ToString(cidr.Description),
		})
	}

	// Handle referenced security groups
	for _, group := range rule.UserIdGroupPairs {
		rules = append(rules, state.SecurityGroupRule{
			Type:        "ingress",
			Protocol:    protocol,
			FromPort:    fromPort,
			ToPort:      toPort,
			GroupID:     aws.ToString(group.GroupId),
			Description: aws.ToString(group.Description),
		})
	}

	return rules
}

// convertEgressRule converts EC2 egress rule to our format
func (sgm *SecurityGroupManager) convertEgressRule(rule types.IpPermission) []state.SecurityGroupRule {
	var rules []state.SecurityGroupRule

	protocol := aws.ToString(rule.IpProtocol)
	fromPort := aws.ToInt32(rule.FromPort)
	toPort := aws.ToInt32(rule.ToPort)

	// Handle CIDR blocks
	for _, cidr := range rule.IpRanges {
		rules = append(rules, state.SecurityGroupRule{
			Type:        "egress",
			Protocol:    protocol,
			FromPort:    fromPort,
			ToPort:      toPort,
			CidrBlocks:  []string{aws.ToString(cidr.CidrIp)},
			Description: aws.ToString(cidr.Description),
		})
	}

	// Handle referenced security groups
	for _, group := range rule.UserIdGroupPairs {
		rules = append(rules, state.SecurityGroupRule{
			Type:        "egress",
			Protocol:    protocol,
			FromPort:    fromPort,
			ToPort:      toPort,
			GroupID:     aws.ToString(group.GroupId),
			Description: aws.ToString(group.Description),
		})
	}

	return rules
}

// AddIngressRule adds a TCP ingress rule to allow access from a specific IP on the given port
func (sgm *SecurityGroupManager) AddIngressRule(ctx context.Context, groupID, clientIP string, port int32) error {
	sgm.logger.LogAction("add_ingress_rule", map[string]interface{}{
		"security_group_id": groupID,
		"client_ip":         clientIP,
		"port":              port,
	})

	cidr := fmt.Sprintf("%s/32", clientIP)

	// First, remove any existing rule for this IP to avoid duplicates
	sgm.RemoveIngressRuleForIP(ctx, groupID, clientIP, port)

	// Add new rule
	_, err := sgm.ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(groupID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(port),
				ToPort:     aws.Int32(port),
				IpRanges: []types.IpRange{
					{
						CidrIp:      aws.String(cidr),
						Description: aws.String(fmt.Sprintf("Access for %s - added by sg-authorizer", clientIP)),
					},
				},
			},
		},
	})

	if err != nil {
		// Check if rule already exists
		if strings.Contains(err.Error(), "already exists") {
			sgm.logger.LogAction("ingress_rule_already_exists", map[string]interface{}{
				"security_group_id": groupID,
				"client_ip":         clientIP,
				"cidr":              cidr,
			})
			return nil // Rule already exists, which is fine
		}

		sgm.logger.LogError("authorize_security_group_ingress", err, map[string]interface{}{
			"security_group_id": groupID,
			"client_ip":         clientIP,
			"cidr":              cidr,
		})
		return fmt.Errorf("failed to add ingress rule: %w", err)
	}

	sgm.logger.LogAWSAction("ec2", "authorize_security_group_ingress", map[string]interface{}{
		"security_group_id": groupID,
		"client_ip":         clientIP,
		"cidr":              cidr,
		"port":              port,
	})

	return nil
}

// RemoveIngressRuleForIP removes the TCP ingress rule for a specific IP on the given port
func (sgm *SecurityGroupManager) RemoveIngressRuleForIP(ctx context.Context, groupID, clientIP string, port int32) error {
	cidr := fmt.Sprintf("%s/32", clientIP)

	sgm.logger.LogAction("remove_ingress_rule", map[string]interface{}{
		"security_group_id": groupID,
		"client_ip":         clientIP,
		"cidr":              cidr,
		"port":              port,
	})

	_, err := sgm.ec2Client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(groupID),
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(port),
				ToPort:     aws.Int32(port),
				IpRanges: []types.IpRange{
					{
						CidrIp: aws.String(cidr),
					},
				},
			},
		},
	})

	if err != nil {
		// Check if rule doesn't exist
		if strings.Contains(err.Error(), "does not exist") {
			sgm.logger.LogAction("ingress_rule_does_not_exist", map[string]interface{}{
				"security_group_id": groupID,
				"client_ip":         clientIP,
				"cidr":              cidr,
			})
			return nil // Rule doesn't exist, which is fine
		}

		sgm.logger.LogError("revoke_security_group_ingress", err, map[string]interface{}{
			"security_group_id": groupID,
			"client_ip":         clientIP,
			"cidr":              cidr,
		})
		return fmt.Errorf("failed to remove ingress rule: %w", err)
	}

	sgm.logger.LogAWSAction("ec2", "revoke_security_group_ingress", map[string]interface{}{
		"security_group_id": groupID,
		"client_ip":         clientIP,
		"cidr":              cidr,
		"port":              port,
	})

	return nil
}

// RestoreOriginalRules restores security group to its original state
func (sgm *SecurityGroupManager) RestoreOriginalRules(ctx context.Context, groupID string, originalState *state.SecurityGroupState) error {
	sgm.logger.LogAction("restore_original_rules", map[string]interface{}{
		"security_group_id": groupID,
		"original_rules":    len(originalState.Rules),
	})

	// Get current rules
	currentRules, err := sgm.GetSecurityGroupRules(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to get current rules: %w", err)
	}

	// Remove rules that shouldn't be there
	for _, currentRule := range currentRules {
		if !sgm.ruleExistsInOriginal(currentRule, originalState.Rules) {
			if err := sgm.removeRule(ctx, groupID, currentRule); err != nil {
				sgm.logger.LogError("remove_extra_rule", err, map[string]interface{}{
					"security_group_id": groupID,
					"rule":              currentRule,
				})
				// Continue with other rules even if one fails
			}
		}
	}

	// Add rules that should be there
	for _, originalRule := range originalState.Rules {
		if !sgm.ruleExistsInCurrent(originalRule, currentRules) {
			if err := sgm.addRule(ctx, groupID, originalRule); err != nil {
				sgm.logger.LogError("add_missing_rule", err, map[string]interface{}{
					"security_group_id": groupID,
					"rule":              originalRule,
				})
				// Continue with other rules even if one fails
			}
		}
	}

	sgm.logger.LogAction("restore_completed", map[string]interface{}{
		"security_group_id": groupID,
	})

	return nil
}

// Helper functions
func getHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	return keys
}

func (sgm *SecurityGroupManager) ruleExistsInOriginal(rule state.SecurityGroupRule, originalRules []state.SecurityGroupRule) bool {
	for _, originalRule := range originalRules {
		if sgm.rulesEqual(rule, originalRule) {
			return true
		}
	}
	return false
}

func (sgm *SecurityGroupManager) ruleExistsInCurrent(rule state.SecurityGroupRule, currentRules []state.SecurityGroupRule) bool {
	for _, currentRule := range currentRules {
		if sgm.rulesEqual(rule, currentRule) {
			return true
		}
	}
	return false
}

func (sgm *SecurityGroupManager) rulesEqual(rule1, rule2 state.SecurityGroupRule) bool {
	return rule1.Type == rule2.Type &&
		rule1.Protocol == rule2.Protocol &&
		rule1.FromPort == rule2.FromPort &&
		rule1.ToPort == rule2.ToPort &&
		sgm.slicesEqual(rule1.CidrBlocks, rule2.CidrBlocks) &&
		rule1.GroupID == rule2.GroupID
}

func (sgm *SecurityGroupManager) slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func (sgm *SecurityGroupManager) removeRule(ctx context.Context, groupID string, rule state.SecurityGroupRule) error {
	if rule.Type == "ingress" {
		return sgm.removeIngressRule(ctx, groupID, rule)
	}
	return sgm.removeEgressRule(ctx, groupID, rule)
}

func (sgm *SecurityGroupManager) addRule(ctx context.Context, groupID string, rule state.SecurityGroupRule) error {
	if rule.Type == "ingress" {
		return sgm.addIngressRule(ctx, groupID, rule)
	}
	return sgm.addEgressRule(ctx, groupID, rule)
}

func (sgm *SecurityGroupManager) removeIngressRule(ctx context.Context, groupID string, rule state.SecurityGroupRule) error {
	permission := sgm.buildIpPermission(rule)

	_, err := sgm.ec2Client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId:       aws.String(groupID),
		IpPermissions: []types.IpPermission{permission},
	})

	return err
}

func (sgm *SecurityGroupManager) removeEgressRule(ctx context.Context, groupID string, rule state.SecurityGroupRule) error {
	permission := sgm.buildIpPermission(rule)

	_, err := sgm.ec2Client.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{
		GroupId:       aws.String(groupID),
		IpPermissions: []types.IpPermission{permission},
	})

	return err
}

func (sgm *SecurityGroupManager) addIngressRule(ctx context.Context, groupID string, rule state.SecurityGroupRule) error {
	permission := sgm.buildIpPermission(rule)

	_, err := sgm.ec2Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId:       aws.String(groupID),
		IpPermissions: []types.IpPermission{permission},
	})

	return err
}

func (sgm *SecurityGroupManager) addEgressRule(ctx context.Context, groupID string, rule state.SecurityGroupRule) error {
	permission := sgm.buildIpPermission(rule)

	_, err := sgm.ec2Client.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId:       aws.String(groupID),
		IpPermissions: []types.IpPermission{permission},
	})

	return err
}

func (sgm *SecurityGroupManager) buildIpPermission(rule state.SecurityGroupRule) types.IpPermission {
	permission := types.IpPermission{
		IpProtocol: aws.String(rule.Protocol),
		FromPort:   aws.Int32(rule.FromPort),
		ToPort:     aws.Int32(rule.ToPort),
	}

	if len(rule.CidrBlocks) > 0 {
		for _, cidr := range rule.CidrBlocks {
			permission.IpRanges = append(permission.IpRanges, types.IpRange{
				CidrIp:      aws.String(cidr),
				Description: aws.String(rule.Description),
			})
		}
	}

	if rule.GroupID != "" {
		permission.UserIdGroupPairs = append(permission.UserIdGroupPairs, types.UserIdGroupPair{
			GroupId:     aws.String(rule.GroupID),
			Description: aws.String(rule.Description),
		})
	}

	return permission
}
