// Package audit provides audit logging capabilities for HostingMaster services.
// This package contains the interface that all services must implement.
// See ADR-0012 for details on audit logging implementation.

package audit

import (
	"context"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Action represents the type of action being audited.
type Action string

const (
	// ActionCreate indicates a resource was created.
	ActionCreate Action = "CREATE"
	// ActionRead indicates a resource was read/accessed.
	ActionRead Action = "READ"
	// ActionUpdate indicates a resource was updated.
	ActionUpdate Action = "UPDATE"
	// ActionDelete indicates a resource was deleted.
	ActionDelete Action = "DELETE"
	// ActionLogin indicates a user login event.
	ActionLogin Action = "LOGIN"
	// ActionLogout indicates a user logout event.
	ActionLogout Action = "LOGOUT"
	// ActionPasswordChange indicates a password was changed.
	ActionPasswordChange Action = "PASSWORD_CHANGE"
	// ActionTwoFAEnable indicates 2FA was enabled.
	ActionTwoFAEnable Action = "2FA_ENABLE"
	// ActionTwoFADisable indicates 2FA was disabled.
	ActionTwoFADisable Action = "2FA_DISABLE"
)

// Status represents the outcome of an audited action.
type Status string

const (
	// StatusSuccess indicates the action completed successfully.
	StatusSuccess Status = "SUCCESS"
	// StatusFailure indicates the action failed.
	StatusFailure Status = "FAILURE"
	// StatusStarted indicates the action was started (for long-running operations).
	StatusStarted Status = "STARTED"
)

// LogEntry represents a single audit log entry.
type LogEntry struct {
	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp" bson:"timestamp"`
	// TenantID is the tenant context for the event.
	TenantID string `json:"tenantId" bson:"tenantId"`
	// UserID is the user who performed the action.
	UserID string `json:"userId" bson:"userId,omitempty"`
	// Username is the username of the user.
	Username string `json:"username" bson:"username,omitempty"`
	// Action is what action was performed.
	Action Action `json:"action" bson:"action"`
	// Status is the outcome of the action.
	Status Status `json:"status" bson:"status"`
	// ResourceType is the type of resource affected (e.g., "user", "tenant", "token").
	ResourceType string `json:"resourceType" bson:"resourceType,omitempty"`
	// ResourceID is the identifier of the resource.
	ResourceID string `json:"resourceId" bson:"resourceId,omitempty"`
	// IPAddress is the client IP address.
	IPAddress string `json:"ipAddress" bson:"ipAddress,omitempty"`
	// UserAgent is the client user agent.
	UserAgent string `json:"userAgent" bson:"userAgent,omitempty"`
	// Details contains additional context-specific information.
	Details map[string]any `json:"details" bson:"details,omitempty"`
	// Error contains error information if Status is StatusFailure.
	Error string `json:"error,omitempty" bson:"error,omitempty"`
}

// Logger is the interface that audit log implementations must satisfy.
// Each service (e.g., auth-service) must provide its own implementation
// that persists audit logs to the appropriate storage (e.g., MongoDB).
//
// IMPORTANT: Implementations MUST handle persistence ASYNCHRONOUSLY to avoid
// blocking the main request flow. Use channels, goroutines, or async storage drivers.
type Logger interface {
	// Log records an audit log entry asynchronously.
	// Implementations MUST NOT block the calling goroutine.
	Log(ctx context.Context, entry LogEntry) error
	// LogWithContext is a convenience method that extracts tenant and user info from context.
	// If tenant or user info is not available in context, it should still log with available info.
	// Implementations MUST NOT block the calling goroutine.
	LogWithContext(ctx context.Context, action Action, status Status, details map[string]any) error
}

// NoOpLogger is a no-operation implementation of Logger for testing or when audit logging is disabled.
type NoOpLogger struct{}

// Log implements Logger interface - does nothing.
func (*NoOpLogger) Log(_ context.Context, _ LogEntry) error {
	return nil
}

// LogWithContext implements Logger interface - does nothing.
func (*NoOpLogger) LogWithContext(_ context.Context, _ Action, _ Status, _ map[string]any) error {
	return nil
}

// contextKey is the key for audit logger in context.
type contextKey struct{}

// WithLogger stores the audit logger in the context.
func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

// FromContext retrieves the audit logger from the context.
// Returns NoOpLogger if no logger is set.
//
//nolint:ireturn // Returns Logger interface - this is a valid pattern for context value retrieval
func FromContext(ctx context.Context) Logger {
	if logger, ok := ctx.Value(contextKey{}).(Logger); ok {
		return logger
	}

	return &NoOpLogger{}
}

// ExtractClientInfo extracts IP address and User-Agent from gRPC context.
// It uses gRPC peer information for IP and metadata for User-Agent.
// Returns IP, User-Agent, and error if extraction fails.
func ExtractClientInfo(ctx context.Context) (string, string, error) {
	var ipAddress, userAgent string

	// Extract IP from peer address
	p, ok := peer.FromContext(ctx)
	if ok && p.Addr != nil {
		addr := p.Addr.String()

		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			ipAddress = host
		} else if ip := net.ParseIP(addr); ip != nil {
			ipAddress = ip.String()
		} else {
			ipAddress = addr // Fallback to raw address
		}
	}

	// Extract User-Agent from metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		userAgents := md.Get("user-agent")
		if len(userAgents) > 0 {
			userAgent = userAgents[0]
		}
	}

	return ipAddress, userAgent, nil
}

// SanitizeDetails removes potentially sensitive information from audit log details.
// This prevents PII leaks in audit logs (e.g., passwords, tokens, credit card numbers).
// The function modifies the map in place.
func SanitizeDetails(details map[string]any) {
	if details == nil {
		return
	}

	// Keys that should never appear in audit logs
	sensitiveKeys := []string{
		"password",
		"password_hash",
		"passwordhash",
		"token",
		"access_token",
		"refresh_token",
		"api_key",
		"apikey",
		"secret",
		"credit_card",
		"creditcard",
		"cc_number",
		"authorization",
		"auth",
		"cookie",
		"set-cookie",
		"private_key",
		"privatekey",
	}

	// Collect all keys to delete (including case-insensitive matches)
	keysToDelete := make(map[string]bool)
	for _, sensitiveKey := range sensitiveKeys {
		keysToDelete[sensitiveKey] = true
		// Collect case-insensitive matches
		for k := range details {
			if strings.EqualFold(k, sensitiveKey) {
				keysToDelete[k] = true
			}
		}
	}

	// Delete all sensitive keys
	for k := range keysToDelete {
		delete(details, k)
	}
}
