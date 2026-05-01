// Package grpc provides gRPC middleware for HostingMaster services.
// This package extends the existing tenant interceptors with authentication capabilities.

package grpc

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"hostingmaster.io/hm-lib/jwt"
	"hostingmaster.io/hm-lib/tenants"
)

// AuthInterceptor returns a gRPC unary server interceptor that validates JWT tokens
// and sets both tenant and user context.
// The JWT validator must be provided by the consuming service (e.g., auth-service).
// Keys are loaded from Kubernetes Secrets by the service.
func AuthInterceptor(validator jwt.Validator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Extract token from metadata
		token, err := extractTokenFromMetadata(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "missing or invalid authorization token: %v", err)
		}

		// Validate token
		claims, err := validator.ValidateToken(token)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		// Set tenant context (from JWT claims)
		ctx = tenant.WithTenant(ctx, claims.TenantID)

		// Set user context (optional - could be a separate package)
		// For now, we just ensure tenant context is set
		// User context would be: ctx = user.WithUser(ctx, claims.UserID, claims.Username, claims.Roles)

		return handler(ctx, req)
	}
}

// StreamAuthInterceptor returns a gRPC stream server interceptor that validates JWT tokens
// and sets both tenant and user context for streaming RPCs.
func StreamAuthInterceptor(validator jwt.Validator) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Extract token from metadata
		token, err := extractTokenFromMetadata(ss.Context())
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "missing or invalid authorization token: %v", err)
		}

		// Validate token
		claims, err := validator.ValidateToken(token)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		// Set tenant context
		ctx := tenant.WithTenant(ss.Context(), claims.TenantID)

		// Wrap the server stream with the new context
		wrappedStream := &tenantAwareStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		return handler(srv, wrappedStream)
	}
}

// extractTokenFromMetadata extracts the JWT token from gRPC metadata.
// It checks for the "authorization" header with "Bearer <token>" format.
func extractTokenFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no metadata in context")
	}

	// Check Authorization header
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "authorization header missing")
	}

	// Parse "Bearer <token>" format
	token := authHeaders[0]
	if !strings.HasPrefix(token, "Bearer ") {
		return "", status.Error(codes.Unauthenticated, "authorization header must start with 'Bearer '")
	}

	// Remove "Bearer " prefix and any leading/trailing whitespace
	return strings.TrimSpace(strings.TrimPrefix(token, "Bearer ")), nil
}

// tenantAwareStream wraps a ServerStream to provide context with tenant ID.
// This is used by StreamAuthInterceptor to propagate tenant context.
type tenantAwareStream struct {
	grpc.ServerStream

	ctx context.Context
}

// Context returns the context with tenant ID.
func (ss *tenantAwareStream) Context() context.Context {
	return ss.ctx
}

// UnaryAuthInterceptorWithTenantOnly returns a simpler interceptor that only sets tenant context
// from the x-tenant-id metadata (for services that don't need JWT auth).
// This is the existing TenantInterceptor renamed for clarity.
func UnaryAuthInterceptorWithTenantOnly() grpc.UnaryServerInterceptor {
	return TenantInterceptor()
}

// CombineInterceptors combines multiple unary interceptors into one.
// The interceptors are executed in the order they are provided.
func CombineInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Build the chain from right to left (last interceptor wraps the handler first)
		var combined grpc.UnaryHandler = handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			prevHandler := combined
			combined = func(ctx context.Context, req interface{}) (interface{}, error) {
				return interceptor(ctx, req, info, prevHandler)
			}
		}
		return combined(ctx, req)
	}
}
