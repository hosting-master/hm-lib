package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//nolint:wrapcheck
func generateTestKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, &privateKey.PublicKey, nil
}

//nolint:wrapcheck
func generateTestToken(privateKey *rsa.PrivateKey, claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(privateKey)
}

//nolint:cyclop,gocyclo,funlen
func TestRS256Validator_ValidateToken(t *testing.T) {
	t.Parallel()

	privateKey, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	validator := NewRS256Validator(publicKey)

	tests := []struct {
		name        string
		claims      Claims
		tokenFunc   func(*rsa.PrivateKey, Claims) (string, error)
		wantErr     bool
		wantErrType error
		checkFunc   func(*testing.T, *Claims)
	}{
		{
			name: "valid token",
			claims: Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer:    "hostingmaster",
					Subject:   "user-123",
				},
				Username: "testuser",
				Roles:    []string{"customer"},
				TenantID: "tenant-456",
			},
			tokenFunc: generateTestToken,
			wantErr:   false,
			checkFunc: func(t *testing.T, claims *Claims) {
				t.Helper()

				if claims.Subject != "user-123" {
					t.Errorf("got Subject (UserID) %q, want %q", claims.Subject, "user-123")
				}

				if claims.Username != "testuser" {
					t.Errorf("got Username %q, want %q", claims.Username, "testuser")
				}

				if len(claims.Roles) != 1 || claims.Roles[0] != "customer" {
					t.Errorf("got Roles %v, want [customer]", claims.Roles)
				}

				if claims.TenantID != "tenant-456" {
					t.Errorf("got TenantID %q, want %q", claims.TenantID, "tenant-456")
				}
			},
		},
		{
			name:        "expired token",
			claims:      Claims{RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))}},
			tokenFunc:   generateTestToken,
			wantErr:     true,
			wantErrType: ErrTokenExpired,
		},
		{
			name:        "not yet valid token",
			claims:      Claims{RegisteredClaims: jwt.RegisteredClaims{NotBefore: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}},
			tokenFunc:   generateTestToken,
			wantErr:     true,
			wantErrType: ErrTokenNotYetValid,
		},
		{
			name:   "invalid signature",
			claims: Claims{RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour))}},
			tokenFunc: func(*rsa.PrivateKey, Claims) (string, error) {
				// Generate token with different key
				otherKey, _, _ := generateTestKeyPair()

				return generateTestToken(otherKey, Claims{})
			},
			wantErr:     true,
			wantErrType: ErrInvalidToken,
		},
		{
			name:   "wrong signing method",
			claims: Claims{},
			tokenFunc: func(*rsa.PrivateKey, Claims) (string, error) {
				// Generate HS256 token (wrong method)
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"test": "value"})

				return token.SignedString([]byte("secret"))
			},
			wantErr:     true,
			wantErrType: ErrInvalidToken,
		},
		{
			name:   "invalid token format",
			claims: Claims{},
			tokenFunc: func(*rsa.PrivateKey, Claims) (string, error) {
				return "not.a.valid.token", nil
			},
			wantErr:     true,
			wantErrType: ErrInvalidToken,
		},
		{
			name:   "empty token",
			claims: Claims{},
			tokenFunc: func(*rsa.PrivateKey, Claims) (string, error) {
				return "", nil
			},
			wantErr:     true,
			wantErrType: ErrInvalidToken,
		},
		{
			name:   "alg none token (CVE-2015-2951 attack vector)",
			claims: Claims{},
			tokenFunc: func(*rsa.PrivateKey, Claims) (string, error) {
				// Create a token with alg: none - should be rejected by WithValidMethods
				token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"test": "value"})

				return token.SignedString(jwt.UnsafeAllowNoneSignatureType)
			},
			wantErr:     true,
			wantErrType: ErrInvalidToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token, err := tc.tokenFunc(privateKey, tc.claims)
			if err != nil {
				t.Fatalf("failed to generate token: %v", err)
			}

			claims, err := validator.ValidateToken(token)

			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateToken() error = %v, wantErr %v", err, tc.wantErr)

				return
			}

			if tc.wantErr {
				if tc.wantErrType != nil && !errors.Is(err, tc.wantErrType) {
					t.Errorf("ValidateToken() error type = %T, want %T", err, tc.wantErrType)
				}

				return
			}

			if tc.checkFunc != nil {
				tc.checkFunc(t, claims)
			}
		})
	}
}

func TestClaims_GetExpiryDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		exp     *jwt.NumericDate
		wantDur time.Duration
	}{
		{
			name:    "token expires in 1 hour",
			exp:     jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			wantDur: 1 * time.Hour,
		},
		{
			name:    "token expires in 30 minutes",
			exp:     jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			wantDur: 30 * time.Minute,
		},
		{
			name:    "token already expired",
			exp:     jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			wantDur: -1 * time.Hour,
		},
		{
			name:    "token never expires",
			exp:     nil,
			wantDur: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: tc.exp}}
			got := claims.GetExpiryDuration()
			// Allow 1 second tolerance for timing differences between token creation and check
			diff := got - tc.wantDur
			if diff < -1*time.Second || diff > 1*time.Second {
				t.Errorf("GetExpiryDuration() = %v, want %v (diff: %v)", got, tc.wantDur, diff)
			}
		})
	}
}

func TestClaims_IsExpired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		exp  *jwt.NumericDate
		want bool
	}{
		{
			name: "token not expired",
			exp:  jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			want: false,
		},
		{
			name: "token expired",
			exp:  jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			want: true,
		},
		{
			name: "token never expires",
			exp:  nil,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: tc.exp}}
			if got := claims.IsExpired(); got != tc.want {
				t.Errorf("IsExpired() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParsePublicKeyFromPEM(t *testing.T) {
	t.Parallel()

	_, publicKey, err := generateTestKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Encode public key to PEM format
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	})

	parsedKey, err := ParsePublicKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM() error = %v", err)
	}

	if parsedKey.E != publicKey.E || parsedKey.N.Cmp(publicKey.N) != 0 {
		t.Error("ParsePublicKeyFromPEM() returned different key")
	}
}
