package rate

import (
	"testing"
	"time"
)

func TestInMemoryLimiter_Allow(t *testing.T) {
	limiter := NewInMemoryLimiter(3, 1*time.Minute)

	key := "test-key"

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		if !limiter.Allow(key) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 4th request should be denied
	if limiter.Allow(key) {
		t.Error("4th request should be denied")
	}
}

func TestInMemoryLimiter_Remaining(t *testing.T) {
	limiter := NewInMemoryLimiter(3, 1*time.Minute)
	key := "test-key"

	// Initially should have 3 remaining
	if remaining := limiter.Remaining(key); remaining != 3 {
		t.Errorf("Remaining() = %v, want 3", remaining)
	}

	// After 1 request, should have 2 remaining
	limiter.Allow(key)
	if remaining := limiter.Remaining(key); remaining != 2 {
		t.Errorf("Remaining() = %v, want 2", remaining)
	}

	// After 3 requests, should have 0 remaining
	limiter.Allow(key)
	limiter.Allow(key)
	if remaining := limiter.Remaining(key); remaining != 0 {
		t.Errorf("Remaining() = %v, want 0", remaining)
	}
}

func TestInMemoryLimiter_ResetAt(t *testing.T) {
	limiter := NewInMemoryLimiter(5, 1*time.Minute)
	key := "test-key"

	// First request
	limiter.Allow(key)
	resetAt := limiter.ResetAt(key)

	// Reset time should be approximately 1 minute from now
	now := time.Now()
	expectedReset := now.Add(1 * time.Minute)
	if resetAt.Before(expectedReset.Add(-1*time.Second)) || resetAt.After(expectedReset.Add(1*time.Second)) {
		t.Errorf("ResetAt() = %v, want approximately %v", resetAt, expectedReset)
	}
}

func TestInMemoryLimiter_Limit(t *testing.T) {
	limiter := NewInMemoryLimiter(10, 2*time.Minute)
	limit := limiter.Limit()

	if limit.Requests != 10 {
		t.Errorf("Limit().Requests = %v, want 10", limit.Requests)
	}
	if limit.Window != 2*time.Minute {
		t.Errorf("Limit().Window = %v, want 2m0s", limit.Window)
	}
}

func TestInMemoryLimiter_DifferentKeys(t *testing.T) {
	limiter := NewInMemoryLimiter(2, 1*time.Minute)

	// Use up limit for key1
	limiter.Allow("key1")
	limiter.Allow("key1")

	// key1 should be denied
	if limiter.Allow("key1") {
		t.Error("key1 should be denied after 2 requests")
	}

	// key2 should still be allowed
	if !limiter.Allow("key2") {
		t.Error("key2 should be allowed (separate limit)")
	}
}

func TestInMemoryLimiter_WindowExpiry(t *testing.T) {
	// Use a very short window for testing
	limiter := NewInMemoryLimiter(2, 100*time.Millisecond)
	key := "test-key"

	// Use up the limit
	limiter.Allow(key)
	limiter.Allow(key)

	// Should be denied
	if limiter.Allow(key) {
		t.Error("Should be denied before window resets")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	if !limiter.Allow(key) {
		t.Error("Should be allowed after window resets")
	}
}

func TestKeyBuilder_ForIP(t *testing.T) {
	kb := NewKeyBuilder("auth")
	key := kb.ForIP("192.168.1.1")
	expected := "auth:ip:192.168.1.1"
	if key != expected {
		t.Errorf("ForIP() = %v, want %v", key, expected)
	}
}

func TestKeyBuilder_ForUser(t *testing.T) {
	kb := NewKeyBuilder("api")
	key := kb.ForUser("user-123")
	expected := "api:user:user-123"
	if key != expected {
		t.Errorf("ForUser() = %v, want %v", key, expected)
	}
}

func TestKeyBuilder_ForTenant(t *testing.T) {
	kb := NewKeyBuilder("auth")
	key := kb.ForTenant("tenant-456")
	expected := "auth:tenant:tenant-456"
	if key != expected {
		t.Errorf("ForTenant() = %v, want %v", key, expected)
	}
}

func TestKeyBuilder_ForCombined(t *testing.T) {
	kb := NewKeyBuilder("rate")
	key := kb.ForCombined("ip", "192.168.1.1", "user", "user-123")
	expected := "rate:ip:192.168.1.1:user:user-123:"
	if key != expected {
		t.Errorf("ForCombined() = %v, want %v", key, expected)
	}
}

func TestPresetLimits(t *testing.T) {
	// Verify preset limits are correctly defined
	if LoginLimit.Requests != 5 || LoginLimit.Window != 1*time.Minute {
		t.Errorf("LoginLimit = %+v, want {Requests:5, Window:1m}", LoginLimit)
	}
	if APILimit.Requests != 100 || APILimit.Window != 1*time.Minute {
		t.Errorf("APILimit = %+v, want {Requests:100, Window:1m}", APILimit)
	}
	if PasswordResetLimit.Requests != 3 || PasswordResetLimit.Window != 1*time.Hour {
		t.Errorf("PasswordResetLimit = %+v, want {Requests:3, Window:1h}", PasswordResetLimit)
	}
	if TokenRefreshLimit.Requests != 10 || TokenRefreshLimit.Window != 1*time.Minute {
		t.Errorf("TokenRefreshLimit = %+v, want {Requests:10, Window:1m}", TokenRefreshLimit)
	}
}
