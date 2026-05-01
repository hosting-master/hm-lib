// Package crypto provides cryptographic utilities for HostingMaster services.
// This package is part of hm-lib and contains only generic implementations.

package crypto

import (
	"errors"
	"fmt"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// ErrPasswordTooShort is returned when password is shorter than minimum length.
var ErrPasswordTooShort = errors.New("password too short")

// ErrPasswordMissingUppercase is returned when password is missing uppercase letters.
var ErrPasswordMissingUppercase = errors.New("password missing uppercase letter")

// ErrPasswordMissingLowercase is returned when password is missing lowercase letters.
var ErrPasswordMissingLowercase = errors.New("password missing lowercase letter")

// ErrPasswordMissingDigit is returned when password is missing digits.
var ErrPasswordMissingDigit = errors.New("password missing digit")

// ErrPasswordMissingSpecial is returned when password is missing special characters.
var ErrPasswordMissingSpecial = errors.New("password missing special character")

// ErrPasswordContainsNullByte is returned when password contains null bytes.
var ErrPasswordContainsNullByte = errors.New("password contains null byte")

// DefaultBcryptCost is the minimum cost factor for bcrypt as per ADR-0012.
// Cost of 12 means 2^12 iterations (4096), which is the recommended minimum.
const DefaultBcryptCost = 12

// DefaultPasswordMinLength is the minimum password length requirement.
const DefaultPasswordMinLength = 12

// HashPassword hashes a password using bcrypt with the default cost factor.
// This function is safe for concurrent use.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), DefaultBcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(bytes), nil
}

// CheckPasswordHash compares a plain text password with a bcrypt hash.
// Returns nil on success, error on failure.
func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return fmt.Errorf("password hash mismatch: %w", err)
	}

	return nil
}

// ValidatePasswordStrength checks if a password meets minimum requirements.
// Requirements (per ADR-0012):
// - Minimum 12 characters
// - At least 1 uppercase letter
// - At least 1 lowercase letter
// - At least 1 digit
// - At least 1 special character (!@#$%^&* etc.)
// - Only alphanumeric and common special characters allowed.
func ValidatePasswordStrength(password string) error {
	if len(password) < DefaultPasswordMinLength {
		return ErrPasswordTooShort
	}

	if !hasUppercase(password) {
		return ErrPasswordMissingUppercase
	}

	if !hasLowercase(password) {
		return ErrPasswordMissingLowercase
	}

	if !hasDigit(password) {
		return ErrPasswordMissingDigit
	}

	if !hasSpecial(password) {
		return ErrPasswordMissingSpecial
	}

	if !validCharacters(password) {
		return ErrPasswordContainsNullByte
	}

	return nil
}

func hasUppercase(s string) bool {
	for _, c := range s {
		if unicode.IsUpper(c) {
			return true
		}
	}

	return false
}

func hasLowercase(s string) bool {
	for _, c := range s {
		if unicode.IsLower(c) {
			return true
		}
	}

	return false
}

func hasDigit(s string) bool {
	for _, c := range s {
		if unicode.IsDigit(c) {
			return true
		}
	}

	return false
}

func hasSpecial(s string) bool {
	for _, c := range s {
		if unicode.IsPunct(c) || unicode.IsSymbol(c) {
			return true
		}
	}

	return false
}

func validCharacters(s string) bool {
	// Check for null bytes which are never allowed
	for _, c := range s {
		if c == '\x00' {
			return false
		}
	}

	return true
}
