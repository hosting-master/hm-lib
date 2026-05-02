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

		// Validate token (claims are validated but not used per ADR-0012 Phase 1)
		_, err = validator.ValidateToken(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}

		// Note: Per ADR-0012 Phase 1, JWT contains no tenant information.
		// Tenant context must be set separately via TenantInterceptor.

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

		// Validate token (claims are validated but not used per ADR-0012 Phase 1)
		_, err = validator.ValidateToken(token)
		if err != nil {
			return status.Error(codes.Unauthenticated, "unauthenticated")
		}

		// Note: Per ADR-0012 Phase 1, JWT contains no tenant information.
		// Tenant context must be set separately via StreamTenantInterceptor.

		// Wrap the server stream with the existing context
		wrappedStream := &tenantAwareServerStream{
			ServerStream: serverStream,
			ctx:          serverStream.Context(),
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

	// RFC 6750 Section 2.1: auth-scheme = token68 / ( token68 1*SP ( token68 / ":" ) )
	// For Bearer: "Bearer" SP token68
	// We need exactly: "Bearer" + single space + token (no leading/trailing spaces in token)
	const bearerScheme = "Bearer"

	const minLength = len(bearerScheme) + 1 + 1 // "Bearer" + space + at least 1 char

	if len(token) < minLength {
		return "", ErrInvalidBearerFmt
	}

	// Check scheme is "Bearer" (case-insensitive)
	if !strings.EqualFold(token[:len(bearerScheme)], bearerScheme) {
		return "", ErrInvalidBearerFmt
	}

	// Check there's exactly one space after the scheme
	if token[len(bearerScheme)] != ' ' {
		return "", ErrInvalidBearerFmt
	}

	// Extract token part after the single space
	token = token[len(bearerScheme)+1:]
	if token == "" {
		return "", ErrInvalidBearerFmt
	}

	// RFC 6750: token68 should not have leading or trailing whitespace
	// But some implementations send tokens with trailing spaces, be lenient on trailing only
	if strings.HasPrefix(token, " ") {
		return "", ErrInvalidBearerFmt
	}

	return token, nil
}

// UnaryAuthInterceptorWithTenantOnly returns a simpler interceptor that only sets tenant context
// from the x-tenant-id metadata (for services that don't need JWT auth).
// This is the existing TenantInterceptor renamed for clarity.
func UnaryAuthInterceptorWithTenantOnly() grpc.UnaryServerInterceptor {
	return TenantInterceptor()
}
