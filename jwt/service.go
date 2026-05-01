// Package jwt provides JWT (JSON Web Token) functionality for HostingMaster services.
// This package is part of hm-lib and provides only token VALIDATION (not key management).
// JWT keys are managed by individual services (e.g., auth-service) using Kubernetes Secrets.
// See ADR-0012 for details on JWT implementation.

package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
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
type Claims struct {
	// Standard claims (Subject is used for UserID)
	jwt.RegisteredClaims

	// HostingMaster specific claims
	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	TenantID string   `json:"tenantId,omitempty"`
}

// GetUserID returns the user ID from the Subject claim.
func (c *Claims) GetUserID() string {
	return c.Subject
}

// SetUserID sets the user ID as the Subject claim.
func (c *Claims) SetUserID(userID string) {
	c.Subject = userID
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
}

// NewRS256Validator creates a new JWT validator with the given RSA public key.
// The public key should be loaded from Kubernetes Secrets by the consuming service.
// See ADR-0012 for key management details.
func NewRS256Validator(publicKey *rsa.PublicKey) *RS256Validator {
	return &RS256Validator{publicKey: publicKey}
}

// ValidateToken validates a JWT token signed with RS256.
func (v *RS256Validator) ValidateToken(token string) (*Claims, error) {
	// Parse token without validation to extract claims
	tokenObj, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		// Verify signing method - ADR-0012 requires exactly RS256
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, ErrInvalidToken
		}

		return v.publicKey, nil
	})
	if err != nil {
		// Use exported JWT errors from v5
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}

		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}

		return nil, ErrInvalidToken
	}

	if !tokenObj.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := tokenObj.Claims.(*Claims)
	if !ok {
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
