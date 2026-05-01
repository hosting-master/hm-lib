package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jwtx "github.com/golang-jwt/jwt/v5"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"hostingmaster.io/hm-lib/jwt"
	tenant "hostingmaster.io/hm-lib/tenants"
)

const successResult = "success"

// mockValidator is a test implementation of jwt.Validator.
type mockValidator struct {
	validToken  string
	validClaims *jwt.Claims
	shouldFail  bool
}

func (v *mockValidator) ValidateToken(token string) (*jwt.Claims, error) {
	if v.shouldFail {
		return nil, jwt.ErrInvalidToken
	}

	if token != v.validToken {
		return nil, jwt.ErrInvalidToken
	}

	return v.validClaims, nil
}

func generateTestTokenWithClaims(privateKey *rsa.PrivateKey, claims jwt.Claims) string {
	token := jwtx.NewWithClaims(jwtx.SigningMethodRS256, claims)
	t, _ := token.SignedString(privateKey)

	return t
}

func TestAuthInterceptor_ValidToken(t *testing.T) {
	t.Parallel()
	// Generate test key and token
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	claims := jwt.Claims{
		RegisteredClaims: jwtx.RegisteredClaims{
			ExpiresAt: jwtx.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwtx.NewNumericDate(time.Now()),
			NotBefore: jwtx.NewNumericDate(time.Now()),
			Subject:   "user-123",
		},
		Username: "testuser",
		Roles:    []string{"customer"},
		TenantID: "tenant-456",
	}

	token := generateTestTokenWithClaims(privateKey, claims)
	validator := jwt.NewRS256Validator(&privateKey.PublicKey)

	interceptor := AuthInterceptor(validator)

	// Create a test handler
	handler := func(ctx context.Context, req any) (any, error) {
		// Verify tenant context is set
		tenantID := tenant.GetTenant(ctx)
		if tenantID != "tenant-456" {
			return nil, status.Errorf(codes.Internal, "expected tenant %q, got %q", "tenant-456", tenantID)
		}

		return successResult, nil
	}

	// Create context with authorization metadata
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Call the interceptor
	_, err = interceptor(ctx, "test-request", &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}, handler)
	if err != nil {
		t.Errorf("AuthInterceptor() error = %v", err)
	}
}

func TestAuthInterceptor_MissingToken(t *testing.T) {
	t.Parallel()

	validator := &mockValidator{shouldFail: false}
	interceptor := AuthInterceptor(validator)

	handler := func(ctx context.Context, req any) (any, error) {
		return successResult, nil
	}

	// Context without authorization
	ctx := context.Background()

	_, err := interceptor(ctx, "test-request", &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}, handler)
	if err == nil {
		t.Error("AuthInterceptor() should error when token is missing")
	}

	statusCode, ok := status.FromError(err)
	if !ok {
		t.Errorf("error should be a status error")
	}

	if statusCode.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", statusCode.Code(), codes.Unauthenticated)
	}
}

func TestAuthInterceptor_InvalidToken(t *testing.T) {
	t.Parallel()

	validator := &mockValidator{shouldFail: true}
	interceptor := AuthInterceptor(validator)

	handler := func(ctx context.Context, req any) (any, error) {
		return successResult, nil
	}

	md := metadata.Pairs("authorization", "Bearer invalid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := interceptor(ctx, "test-request", &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}, handler)
	if err == nil {
		t.Error("AuthInterceptor() should error for invalid token")
	}

	statusCode, ok := status.FromError(err)
	if !ok {
		t.Errorf("error should be a status error")
	}

	if statusCode.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", statusCode.Code(), codes.Unauthenticated)
	}
}

func TestAuthInterceptor_WrongBearerFormat(t *testing.T) {
	t.Parallel()

	validator := &mockValidator{shouldFail: false}
	interceptor := AuthInterceptor(validator)

	handler := func(ctx context.Context, req any) (any, error) {
		return successResult, nil
	}

	// Wrong format (not Bearer)
	md := metadata.Pairs("authorization", "Basic dXNlcjpwYXNz")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := interceptor(ctx, "test-request", &grpc.UnaryServerInfo{FullMethod: "/test.Service/Test"}, handler)
	if err == nil {
		t.Error("AuthInterceptor() should error for wrong bearer format")
	}

	statusCode, ok := status.FromError(err)
	if !ok {
		t.Errorf("error should be a status error")
	}

	if statusCode.Code() != codes.Unauthenticated {
		t.Errorf("error code = %v, want %v", statusCode.Code(), codes.Unauthenticated)
	}
}

func TestExtractTokenFromMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata metadata.MD
		want     string
		wantErr  bool
	}{
		{
			name:     "valid bearer token",
			metadata: metadata.Pairs("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9"),
			want:     "eyJhbGciOiJIUzI1NiJ9",
			wantErr:  false,
		},
		{
			name:     "missing authorization header",
			metadata: metadata.Pairs("other-header", "value"),
			want:     "",
			wantErr:  true,
		},
		{
			name:     "empty authorization header",
			metadata: metadata.Pairs("authorization", ""),
			want:     "",
			wantErr:  true,
		},
		{
			name:     "bearer with spaces",
			metadata: metadata.Pairs("authorization", "Bearer  eyJhbGciOiJIUzI1NiJ9"),
			want:     "eyJhbGciOiJIUzI1NiJ9",
			wantErr:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := metadata.NewIncomingContext(context.Background(), tc.metadata)
			got, err := extractTokenFromMetadata(ctx)

			if (err != nil) != tc.wantErr {
				t.Errorf("extractTokenFromMetadata() error = %v, wantErr %v", err, tc.wantErr)

				return
			}

			if got != tc.want {
				t.Errorf("extractTokenFromMetadata() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCombineInterceptors(t *testing.T) {
	t.Parallel()

	// Create two simple interceptors
	interceptor1 := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Add marker to context
		ctx = context.WithValue(ctx, "marker1", "value1") //nolint:staticcheck

		return handler(ctx, req)
	}

	interceptor2 := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Add another marker
		ctx = context.WithValue(ctx, "marker2", "value2") //nolint:staticcheck

		return handler(ctx, req)
	}

	combined := CombineInterceptors(interceptor1, interceptor2)

	handler := func(ctx context.Context, req any) (any, error) {
		// Verify both markers are present
		if ctx.Value("marker1") == nil {
			return nil, status.Error(codes.Internal, "marker1 not set")
		}

		if ctx.Value("marker2") == nil {
			return nil, status.Error(codes.Internal, "marker2 not set")
		}

		return successResult, nil
	}

	ctx := context.Background()

	result, err := combined(ctx, "test-request", &grpc.UnaryServerInfo{FullMethod: "/test"}, handler)
	if err != nil {
		t.Errorf("Combined interceptors error = %v", err)
	}

	if result != successResult {
		t.Errorf("Combined interceptors result = %v, want %v", result, successResult)
	}
}
