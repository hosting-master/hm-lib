package tenant

import (
	"context"
	"testing"
)

func TestWithTenant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = WithTenant(ctx, "test-tenant-123")

	if got := GetTenant(ctx); got != "test-tenant-123" {
		t.Errorf("GetTenant() = %q, want %q", got, "test-tenant-123")
	}
}

func TestGetTenantEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	if got := GetTenant(ctx); got != "" {
		t.Errorf("GetTenant() = %q, want empty string", got)
	}
}

func TestWithBootstrap(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = WithBootstrap(ctx)

	if !IsBootstrap(ctx) {
		t.Error("IsBootstrap() = false, want true")
	}
}

func TestIsBootstrap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tenantID string
		want     bool
	}{
		{"empty tenant", "", false},
		{"normal tenant", "tenant-1", false},
		{"bootstrap", "bootstrap", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			if tc.tenantID != "" {
				ctx = WithTenant(ctx, tc.tenantID)
			}

			if got := IsBootstrap(ctx); got != tc.want {
				t.Errorf("IsBootstrap() = %v, want %v", got, tc.want)
			}
		})
	}
}
