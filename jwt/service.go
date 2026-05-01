// Package jwt provides JWT (JSON Web Token) functionality for HostingMaster services.
// This package is part of hm-lib and provides only token VALIDATION (not key management).
// JWT keys are managed by individual services (e.g., auth-service) using Kubernetes Secrets.
// See ADR-0012 for details on JWT implementation.

package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken is returned when token validation fails.
var ErrInvalidToken = errors.New("invalid token")

// ErrTokenExpired is returned when token has expired.
var ErrTokenExpired = errors.New("token has expired")

// ErrTokenNotYetValid is returned when token is not yet valid (nbf claim).
var ErrTokenNotYetValid = errors.New("token is not yet valid")

// Claims represents the standard JWT claims with HostingMaster-specific extensions.
// Note: UserID is mapped to the standard "sub" (Subject) claim for compatibility.
// Per ADR-0012 Phase 1: TenantID is NOT populated in JWT tokens. Tenant context
// is managed separately via gRPC metadata (see tenants package).
type Claims struct {
	// Standard claims (Subject is used for UserID)
	jwt.RegisteredClaims

	// HostingMaster specific claims
	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	// TenantID is reserved for future use (Phase 2+). Not populated in Phase 1.
	TenantID string `json:"tenantId,omitempty"`
}

// TokenPair represents a pair of access and refresh tokens.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int32 // Access token lifetime in seconds (typically 900 = 15 minutes)
}

// Validator is the interface for JWT token validation.
// Implementations MUST NOT manage keys - keys are provided externally.
type Validator interface {
	// ValidateToken validates a JWT token and returns claims if valid.
	// Returns ErrInvalidToken, ErrTokenExpired, or ErrTokenNotYetValid for invalid tokens.
	ValidateToken(token string) (*Claims, error)
}

// RS256Validator validates RS256-signed JWT tokens using a provided public key.
// This is the standard implementation for HostingMaster services.
type RS256Validator struct {
	publicKey *rsa.PublicKey
	issuer    string
	audience  string
}

// RS256ValidatorOption configures a RS256Validator.
type RS256ValidatorOption func(*RS256Validator)

// WithIssuer sets the expected issuer for token validation.
func WithIssuer(issuer string) RS256ValidatorOption {
	return func(v *RS256Validator) {
		v.issuer = issuer
	}
}

// WithAudience sets the expected audience for token validation.
func WithAudience(audience string) RS256ValidatorOption {
	return func(v *RS256Validator) {
		v.audience = audience
	}
}

// NewRS256Validator creates a new JWT validator with the given RSA public key.
// The public key should be loaded from Kubernetes Secrets by the consuming service.
// See ADR-0012 for key management details.
// Use WithIssuer and WithAudience options to enable issuer/audience validation.
func NewRS256Validator(publicKey *rsa.PublicKey, opts ...RS256ValidatorOption) *RS256Validator {
	v := &RS256Validator{publicKey: publicKey}
	for _, opt := range opts {
		opt(v)
	}

	return v
}

// ValidateToken validates a JWT token signed with RS256.
func (v *RS256Validator) ValidateToken(token string) (*Claims, error) {
	// Parse token with validation
	tokenObj, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		// Verify signing method - ADR-0012 requires exactly RS256
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, ErrInvalidToken
		}

		return v.publicKey, nil
	})
	if err != nil {
		return v.handleJWTError(err)
	}

	if !tokenObj.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := tokenObj.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Validate issuer and audience if configured
	return v.validateClaims(claims)
}

// handleJWTError handles JWT library errors and maps them to our error types.
func (v *RS256Validator) handleJWTError(err error) (*Claims, error) {
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, ErrTokenExpired
	}

	if errors.Is(err, jwt.ErrTokenNotValidYet) {
		return nil, ErrTokenNotYetValid
	}

	return nil, ErrInvalidToken
}

// validateClaims validates issuer and audience claims if configured.
func (v *RS256Validator) validateClaims(claims *Claims) (*Claims, error) {
	// Validate issuer if configured
	if v.issuer != "" && claims.Issuer != v.issuer {
		return nil, ErrInvalidToken
	}

	// Validate audience if configured
	if v.audience != "" && !slices.Contains(claims.Audience, v.audience) {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ParsePublicKeyFromPEM parses an RSA public key from PEM-encoded data.
// This is a utility function for services to load their public keys from Kubernetes Secrets.
func ParsePublicKeyFromPEM(pemData []byte) (*rsa.PublicKey, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(pemData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return key, nil
}

// GetExpiryDuration returns the remaining time until token expiration.
func (c *Claims) GetExpiryDuration() time.Duration {
	if c.ExpiresAt == nil {
		return 0
	}

	return time.Until(c.ExpiresAt.Time)
}

// IsExpired checks if the token has expired.
func (c *Claims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}

	return time.Now().After(c.ExpiresAt.Time)
}
