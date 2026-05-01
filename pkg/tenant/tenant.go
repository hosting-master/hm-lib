package tenant

import "context"

// TenantContextKey is the key for tenant ID in context.
type TenantContextKey struct{}

// WithTenant stores the tenant ID in the context.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantContextKey{}, tenantID)
}

// GetTenant extracts the tenant ID from the context.
// Returns empty string if no tenant ID is present.
func GetTenant(ctx context.Context) string {
	if tenantID, ok := ctx.Value(TenantContextKey{}).(string); ok {
		return tenantID
	}

	return ""
}

// WithBootstrap sets the context to bootstrap mode.
// Bootstrap mode is used for initial provider creation when no tenant exists yet.
func WithBootstrap(ctx context.Context) context.Context {
	return context.WithValue(ctx, TenantContextKey{}, "bootstrap")
}

// IsBootstrap checks if the context is in bootstrap mode.
func IsBootstrap(ctx context.Context) bool {
	return GetTenant(ctx) == "bootstrap"
}
