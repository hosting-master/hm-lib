package tenant

import (
	"context"
	"testing"
)

func TestWithTenant(t *testing.T) {
	ctx := context.Background()
	ctx = WithTenant(ctx, "test-tenant-123")

	if got := GetTenant(ctx); got != "test-tenant-123" {
		t.Errorf("GetTenant() = %q, want %q", got, "test-tenant-123")
	}
}

func TestGetTenantEmpty(t *testing.T) {
	ctx := context.Background()

	if got := GetTenant(ctx); got != "" {
		t.Errorf("GetTenant() = %q, want empty string", got)
	}
}

func TestWithBootstrap(t *testing.T) {
	ctx := context.Background()
	ctx = WithBootstrap(ctx)

	if !IsBootstrap(ctx) {
		t.Error("IsBootstrap() = false, want true")
	}
}

func TestIsBootstrap(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
		want     bool
	}{
		{"empty tenant", "", false},
		{"normal tenant", "tenant-1", false},
		{"bootstrap", "bootstrap", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.tenantID != "" {
				ctx = WithTenant(ctx, tt.tenantID)
			}

			if got := IsBootstrap(ctx); got != tt.want {
				t.Errorf("IsBootstrap() = %v, want %v", got, tt.want)
			}
		})
	}
}
