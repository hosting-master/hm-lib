// Package rate provides rate limiting utilities for HostingMaster services.
// This package contains helper functions and types for implementing rate limiting
// at the service level.
//
// NOTE: The InMemoryLimiter is for testing and development only.
// For production, implement a distributed limiter (e.g., Redis-based).

package rate

import (
	"time"
)

// Limit represents a rate limit configuration.
type Limit struct {
	// Requests is the maximum number of requests allowed.
	Requests int
	// Window is the time window for the limit.
	Window time.Duration
}

// Limiter is the interface for rate limiting.
// Implementations can use various backends (Redis, in-memory, etc.).
type Limiter interface {
	// Allow checks if a request should be allowed.
	// Returns true if the request is allowed, false if rate limited.
	// The key is typically a combination of IP, user ID, or tenant ID.
	Allow(key string) bool
	// Remaining returns the number of requests remaining for the given key.
	Remaining(key string) int
	// ResetAt returns when the rate limit will reset for the given key.
	ResetAt(key string) time.Time
	// Limit returns the configured limit.
	Limit() Limit
}

// InMemoryLimiter is a simple in-memory rate limiter.
// Note: This is not suitable for distributed systems as the state is local to each instance.
// For production, use a distributed rate limiter (e.g., Redis-based).
type InMemoryLimiter struct {
	limit Limit
	// visitors tracks request counts per key
	visitors map[string]*visitor
}

type visitor struct {
	count    int
	expiresAt time.Time
}

// NewInMemoryLimiter creates a new in-memory rate limiter.
func NewInMemoryLimiter(requests int, window time.Duration) *InMemoryLimiter {
	return &InMemoryLimiter{
		limit:   Limit{Requests: requests, Window: window},
		visitors: make(map[string]*visitor),
	}
}

// Allow implements Limiter interface.
func (l *InMemoryLimiter) Allow(key string) bool {
	l.cleanup()
	v, exists := l.visitors[key]
	if !exists || time.Now().After(v.expiresAt) {
		l.visitors[key] = &visitor{count: 1, expiresAt: time.Now().Add(l.limit.Window)}
		return true
	}
	if v.count < l.limit.Requests {
		v.count++
		return true
	}
	return false
}

// Remaining implements Limiter interface.
func (l *InMemoryLimiter) Remaining(key string) int {
	l.cleanup()
	v, exists := l.visitors[key]
	if !exists || time.Now().After(v.expiresAt) {
		return l.limit.Requests
	}
	return l.limit.Requests - v.count
}

// ResetAt implements Limiter interface.
func (l *InMemoryLimiter) ResetAt(key string) time.Time {
	v, exists := l.visitors[key]
	if !exists {
		return time.Now().Add(l.limit.Window)
	}
	return v.expiresAt
}

// Limit implements Limiter interface.
func (l *InMemoryLimiter) Limit() Limit {
	return l.limit
}

// cleanup removes expired visitors to prevent memory leaks.
func (l *InMemoryLimiter) cleanup() {
	for key, v := range l.visitors {
		if time.Now().After(v.expiresAt) {
			delete(l.visitors, key)
		}
	}
}

// Common rate limit presets for HostingMaster services.
//nolint:gochecknoglobals // Package-level constants for rate limiting configuration
var (
	// LoginLimit: 5 attempts per minute per IP/username.
	LoginLimit = Limit{Requests: 5, Window: 1 * time.Minute}
	// APILimit: 100 requests per minute per tenant.
	APILimit = Limit{Requests: 100, Window: 1 * time.Minute}
	// PasswordResetLimit: 3 attempts per hour per user.
	PasswordResetLimit = Limit{Requests: 3, Window: 1 * time.Hour}
	// TokenRefreshLimit: 10 refreshes per minute per user.
	TokenRefreshLimit = Limit{Requests: 10, Window: 1 * time.Minute}
)

// KeyBuilder helps construct rate limiting keys from various components.
type KeyBuilder struct {
	prefix string
}

// NewKeyBuilder creates a new key builder with the given prefix.
func NewKeyBuilder(prefix string) *KeyBuilder {
	return &KeyBuilder{prefix: prefix}
}

// ForIP creates a key for IP-based rate limiting.
func (kb *KeyBuilder) ForIP(ip string) string {
	return kb.prefix + ":ip:" + ip
}

// ForUser creates a key for user-based rate limiting.
func (kb *KeyBuilder) ForUser(userID string) string {
	return kb.prefix + ":user:" + userID
}

// ForTenant creates a key for tenant-based rate limiting.
func (kb *KeyBuilder) ForTenant(tenantID string) string {
	return kb.prefix + ":tenant:" + tenantID
}

// ForCombined creates a key combining multiple identifiers.
func (kb *KeyBuilder) ForCombined(parts ...string) string {
	key := kb.prefix + ":"
	for _, part := range parts {
		key += part + ":"
	}
	return key
}
