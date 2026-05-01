package audit

import (
	"context"
	"testing"
)

func TestNoOpLogger_Log(t *testing.T) {
	t.Parallel()

	logger := &NoOpLogger{}
	entry := AuditLogEntry{
		Action:   ActionCreate,
		Status:   StatusSuccess,
		TenantID: "tenant-123",
		UserID:   "user-456",
	}

	err := logger.Log(context.Background(), entry)
	if err != nil {
		t.Errorf("NoOpLogger.Log() error = %v", err)
	}
}

func TestNoOpLogger_LogWithContext(t *testing.T) {
	t.Parallel()

	logger := &NoOpLogger{}

	err := logger.LogWithContext(
		context.Background(),
		ActionLogin,
		StatusSuccess,
		map[string]any{"ip_address": "192.168.1.1"},
	)
	if err != nil {
		t.Errorf("NoOpLogger.LogWithContext() error = %v", err)
	}
}

func TestWithLogger(t *testing.T) {
	t.Parallel()

	logger := &NoOpLogger{}
	ctx := WithLogger(context.Background(), logger)

	retrieved := FromContext(ctx)
	if retrieved == nil {
		t.Error("FromContext() returned nil")
	}
}

func TestFromContext_NoLogger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := FromContext(ctx)

	// Should return NoOpLogger when no logger is set
	if _, ok := logger.(*NoOpLogger); !ok {
		t.Errorf("FromContext() should return NoOpLogger when no logger is set, got %T", logger)
	}
}

func TestAuditLogEntry_Fields(t *testing.T) {
	t.Parallel()

	entry := AuditLogEntry{
		Action:       ActionCreate,
		Status:       StatusSuccess,
		TenantID:     "tenant-123",
		UserID:       "user-456",
		Username:     "testuser",
		ResourceType: "user",
		ResourceID:   "user-789",
		IPAddress:    "192.168.1.1",
		UserAgent:    "Mozilla/5.0",
		Details:      map[string]any{"field": "value"},
		Error:        "",
	}

	if entry.Action != ActionCreate {
		t.Errorf("Action = %v, want %v", entry.Action, ActionCreate)
	}

	if entry.Status != StatusSuccess {
		t.Errorf("Status = %v, want %v", entry.Status, StatusSuccess)
	}

	if entry.TenantID != "tenant-123" {
		t.Errorf("TenantID = %v, want %v", entry.TenantID, "tenant-123")
	}

	if entry.Details["field"] != "value" {
		t.Errorf("Details[field] = %v, want %v", entry.Details["field"], "value")
	}
}

func TestActionConstants(t *testing.T) {
	t.Parallel()

	actions := []Action{
		ActionCreate,
		ActionRead,
		ActionUpdate,
		ActionDelete,
		ActionLogin,
		ActionLogout,
		ActionPasswordChange,
		ActionTwoFAEnable,
		ActionTwoFADisable,
	}

	expected := []string{
		"CREATE",
		"READ",
		"UPDATE",
		"DELETE",
		"LOGIN",
		"LOGOUT",
		"PASSWORD_CHANGE",
		"2FA_ENABLE",
		"2FA_DISABLE",
	}

	for i, action := range actions {
		if string(action) != expected[i] {
			t.Errorf("Action %d = %v, want %v", i, string(action), expected[i])
		}
	}
}

func TestStatusConstants(t *testing.T) {
	t.Parallel()

	statuses := []Status{
		StatusSuccess,
		StatusFailure,
		StatusStarted,
	}

	expected := []string{
		"SUCCESS",
		"FAILURE",
		"STARTED",
	}

	for i, status := range statuses {
		if string(status) != expected[i] {
			t.Errorf("Status %d = %v, want %v", i, string(status), expected[i])
		}
	}
}
