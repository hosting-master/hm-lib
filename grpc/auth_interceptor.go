// Package grpc provides gRPC middleware for HostingMaster services.
// This package extends the existing tenant interceptors with authentication capabilities.

package grpc

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"hostingmaster.io/hm-lib/jwt"
	tenant "hostingmaster.io/hm-lib/tenants"
)

// AuthInterceptor returns a gRPC unary server interceptor that validates JWT tokens
// and sets both tenant and user context.
// The JWT validator must be provided by the consuming service (e.g., auth-service).
// Keys are loaded from Kubernetes Secrets by the service.
func AuthInterceptor(validator jwt.Validator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Extract token from metadata
		token, err := extractTokenFromMetadata(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}

		// Validate token
		claims, err := validator.ValidateToken(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}

		// Set tenant context (from JWT claims)
		ctx = tenant.WithTenant(ctx, claims.TenantID)

		return handler(ctx, req)
	}
}

// StreamAuthInterceptor returns a gRPC stream server interceptor that validates JWT tokens
// and sets both tenant and user context for streaming RPCs.
func StreamAuthInterceptor(validator jwt.Validator) grpc.StreamServerInterceptor {
	return func(srv any, serverStream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Extract token from metadata
		token, err := extractTokenFromMetadata(serverStream.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, "unauthenticated")
		}

		// Validate token
		claims, err := validator.ValidateToken(token)
		if err != nil {
			return status.Error(codes.Unauthenticated, "unauthenticated")
		}

		// Set tenant context
		ctx := tenant.WithTenant(serverStream.Context(), claims.TenantID)

		// Wrap the server stream with the new context
		wrappedStream := &tenantAwareStream{
			ServerStream: serverStream,
			ctx:          ctx,
		}

		return handler(srv, wrappedStream)
	}
}

// Sentinel errors for token extraction.
var (
	ErrNoMetadata       = errors.New("no metadata in context")
	ErrNoAuthHeader     = errors.New("authorization header missing")
	ErrInvalidBearerFmt = errors.New("authorization header must start with Bearer")
)

// extractTokenFromMetadata extracts the JWT token from gRPC metadata.
// It checks for the "authorization" header with "Bearer <token>" format.
// Per RFC 6750, the "Bearer" scheme is case-insensitive.
func extractTokenFromMetadata(ctx context.Context) (string, error) {
	metadata, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrNoMetadata
	}

	// Check Authorization header
	authHeaders := metadata.Get("authorization")
	if len(authHeaders) == 0 {
		return "", ErrNoAuthHeader
	}

	// Parse "Bearer <token>" format - case-insensitive per RFC 6750
	token := authHeaders[0]

	const bearerPrefix = "Bearer "

	if len(token) < len(bearerPrefix) {
		return "", ErrInvalidBearerFmt
	}

	// Check if the token starts with "Bearer " (case-insensitive)
	if !strings.EqualFold(token[:len(bearerPrefix)], bearerPrefix) {
		return "", ErrInvalidBearerFmt
	}

	// Extract token part after the prefix

	token = strings.TrimSpace(token[len(bearerPrefix):])
	if token == "" {
		return "", ErrInvalidBearerFmt
	}

	return token, nil
}

// tenantAwareStream wraps a ServerStream to provide context with tenant ID.
// This is used by StreamAuthInterceptor to propagate tenant context.
type tenantAwareStream struct {
	grpc.ServerStream

	// Required to store context in the stream wrapper for gRPC
	ctx context.Context //nolint:containedctx
}

// Context returns the context with tenant ID.
func (s *tenantAwareStream) Context() context.Context {
	return s.ctx
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
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Build the chain from right to left (last interceptor wraps the handler first)
		combined := handler

		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			prevHandler := combined
			combined = func(ctx context.Context, req any) (any, error) {
				return interceptor(ctx, req, info, prevHandler)
			}
		}

		return combined(ctx, req)
	}
}
