package grpc

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockServerStream implements ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream

	ctx context.Context //nolint:containedctx
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SendMsg(msg any) error { return nil }
func (m *mockServerStream) RecvMsg(msg any) error { return nil }

//nolint:funlen
func TestTenantInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		metadata    map[string]string
		method      string
		wantErr     bool
		wantErrCode codes.Code
	}{
		{
			name:     "valid tenant",
			metadata: map[string]string{"x-tenant-id": "tenant-123"},
			method:   "/some.Service/Method",
			wantErr:  false,
		},
		{
			name:        "missing tenant id",
			metadata:    map[string]string{},
			method:      "/some.Service/Method",
			wantErr:     true,
			wantErrCode: codes.Unauthenticated,
		},
		{
			name:     "bootstrap allowed for specific method",
			metadata: map[string]string{},
			method:   "/tenant.v1.TenantService/Bootstrap",
			wantErr:  false,
		},
		{
			name:        "missing metadata",
			metadata:    nil,
			method:      "/some.Service/Method",
			wantErr:     true,
			wantErrCode: codes.Unauthenticated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			if tc.metadata != nil {
				md := metadata.New(tc.metadata)
				ctx = metadata.NewIncomingContext(ctx, md)
			}

			interceptor := TenantInterceptor()

			handler := func(ctx context.Context, req any) (any, error) {
				return nil, nil //nolint:nilnil
			}

			info := &grpc.UnaryServerInfo{
				FullMethod: tc.method,
			}

			_, err := interceptor(ctx, nil, info, handler)

			if (err != nil) != tc.wantErr {
				t.Errorf("interceptor() error = %v, wantErr %v", err, tc.wantErr)

				return
			}

			if err != nil {
				statusCode, ok := status.FromError(err)
				if !ok {
					t.Errorf("error is not a status error")

					return
				}

				if statusCode.Code() != tc.wantErrCode {
					t.Errorf("error code = %v, wantErrCode %v", statusCode.Code(), tc.wantErrCode)
				}
			}
		})
	}
}

//nolint:funlen
func TestStreamTenantInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		metadata    map[string]string
		method      string
		wantErr     bool
		wantErrCode codes.Code
	}{
		{
			name:     "valid tenant",
			metadata: map[string]string{"x-tenant-id": "tenant-123"},
			method:   "/some.Service/Method",
			wantErr:  false,
		},
		{
			name:        "missing tenant id",
			metadata:    map[string]string{},
			method:      "/some.Service/Method",
			wantErr:     true,
			wantErrCode: codes.Unauthenticated,
		},
		{
			name:     "bootstrap allowed for specific method",
			metadata: map[string]string{},
			method:   "/tenant.v1.TenantService/Bootstrap",
			wantErr:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			if tc.metadata != nil {
				md := metadata.New(tc.metadata)
				ctx = metadata.NewIncomingContext(ctx, md)
			}

			interceptor := StreamTenantInterceptor()

			handler := func(srv any, stream grpc.ServerStream) error {
				return nil
			}

			info := &grpc.StreamServerInfo{
				FullMethod: tc.method,
			}

			serverStream := &mockServerStream{
				ctx: ctx,
			}

			err := interceptor(nil, serverStream, info, handler)

			if (err != nil) != tc.wantErr {
				t.Errorf("interceptor() error = %v, wantErr %v", err, tc.wantErr)

				return
			}

			if err != nil {
				statusCode, ok := status.FromError(err)
				if !ok {
					t.Errorf("error is not a status error")

					return
				}

				if statusCode.Code() != tc.wantErrCode {
					t.Errorf("error code = %v, wantErrCode %v", statusCode.Code(), tc.wantErrCode)
				}
			}
		})
	}
}
