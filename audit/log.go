// Package audit provides audit logging capabilities for HostingMaster services.
// This package contains the interface that all services must implement.
// See ADR-0012 for details on audit logging implementation.

package audit

import (
	"context"
	"time"
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

// AuditLogEntry represents a single audit log entry.
type AuditLogEntry struct {
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
	Log(ctx context.Context, entry AuditLogEntry) error
	// LogWithContext is a convenience method that extracts tenant and user info from context.
	// If tenant or user info is not available in context, it should still log with available info.
	// Implementations MUST NOT block the calling goroutine.
	LogWithContext(ctx context.Context, action Action, status Status, details map[string]any) error
}

// NoOpLogger is a no-operation implementation of Logger for testing or when audit logging is disabled.
type NoOpLogger struct{}

// Log implements Logger interface - does nothing.
func (n *NoOpLogger) Log(ctx context.Context, entry AuditLogEntry) error {
	return nil
}

// LogWithContext implements Logger interface - does nothing.
func (n *NoOpLogger) LogWithContext(ctx context.Context, action Action, status Status, details map[string]any) error {
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
