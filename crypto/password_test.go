package crypto

import (
	"errors"
	"testing"
)

func TestHashPassword(t *testing.T) {
	t.Parallel()

	password := "TestPassword123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == "" {
		t.Error("HashPassword() returned empty string")
	}

	// Hash should be different each time (due to salt)
	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == hash2 {
		t.Error("HashPassword() returned same hash for same password (missing salt?)")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	t.Parallel()

	password := "TestPassword123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	// Correct password should pass
	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Errorf("CheckPasswordHash() error = %v for correct password", err)
	}

	// Wrong password should fail
	err = CheckPasswordHash("wrong_password", hash)
	if err == nil {
		t.Error("CheckPasswordHash() did not error for wrong password")
	}

	// Empty password should fail
	err = CheckPasswordHash("", hash)
	if err == nil {
		t.Error("CheckPasswordHash() did not error for empty password")
	}
}

//nolint:funlen // Test function with many test cases
func TestValidatePasswordStrength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{
			name:     "valid password",
			password: "ValidPass123!",
			wantErr:  nil,
		},
		{
			name:     "too short",
			password: "Short1!",
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:     "missing uppercase",
			password: "validpass123!",
			wantErr:  ErrPasswordMissingUppercase,
		},
		{
			name:     "missing lowercase",
			password: "VALIDPASS123!",
			wantErr:  ErrPasswordMissingLowercase,
		},
		{
			name:     "missing digit",
			password: "ValidPassword!",
			wantErr:  ErrPasswordMissingDigit,
		},
		{
			name:     "missing special char",
			password: "ValidPassword123",
			wantErr:  ErrPasswordMissingSpecial,
		},
		{
			name:     "invalid characters",
			password: "ValidPass123!\x00", // Null byte
			wantErr:  ErrPasswordInvalidCharacters,
		},
		{
			name:     "valid with all special chars",
			password: "Test!@#$%^&*()123",
			wantErr:  nil,
		},
		{
			name:     "valid with spaces",
			password: "Test Pass 123!",
			wantErr:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidatePasswordStrength(tc.password)
			if tc.wantErr == nil && err != nil {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr nil", err)
			}

			if tc.wantErr != nil && err == nil {
				t.Errorf("ValidatePasswordStrength() error = nil, wantErr %v", tc.wantErr)
			}

			if tc.wantErr != nil && err != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestBcryptCost(t *testing.T) {
	t.Parallel()
	// Verify that DefaultBcryptCost is at least 12
	if DefaultBcryptCost < 12 {
		t.Errorf("DefaultBcryptCost = %d, want at least 12 (per ADR-0012)", DefaultBcryptCost)
	}
}
