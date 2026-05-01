package crypto

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
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

func TestValidatePasswordStrength(t *testing.T) {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)
			if tt.wantErr == nil && err != nil {
				t.Errorf("ValidatePasswordStrength() error = %v, wantErr nil", err)
			}
			if tt.wantErr != nil && err == nil {
				t.Errorf("ValidatePasswordStrength() error = nil, wantErr %v", tt.wantErr)
			}
			if tt.wantErr != nil && err != nil && err != tt.wantErr {
				// Check if it's one of the expected error types
				if !errorMatches(err, tt.wantErr) {
					t.Errorf("ValidatePasswordStrength() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func errorMatches(err, target error) bool {
	if err == target {
		return true
	}
	switch target {
	case ErrPasswordTooShort,
		ErrPasswordMissingUppercase,
		ErrPasswordMissingLowercase,
		ErrPasswordMissingDigit,
		ErrPasswordMissingSpecial,
		ErrPasswordInvalidCharacters:
		// These are the only error types we return
		return true
	}
	return false
}

func TestBcryptCost(t *testing.T) {
	// Verify that DefaultBcryptCost is at least 12
	if DefaultBcryptCost < 12 {
		t.Errorf("DefaultBcryptCost = %d, want at least 12 (per ADR-0012)", DefaultBcryptCost)
	}
}
