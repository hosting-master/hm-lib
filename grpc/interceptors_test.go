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

	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SendMsg(msg interface{}) error { return nil }
func (m *mockServerStream) RecvMsg(msg interface{}) error { return nil }

func TestTenantInterceptor(t *testing.T) {
	tests := []struct {
		name       string
		metadata   map[string]string
		method     string
		wantErr    bool
		wantErrCode codes.Code
	}{
		{
			name:       "valid tenant",
			metadata:   map[string]string{"x-tenant-id": "tenant-123"},
			method:     "/some.Service/Method",
			wantErr:    false,
		},
		{
			name:       "missing tenant id",
			metadata:   map[string]string{},
			method:     "/some.Service/Method",
			wantErr:    true,
			wantErrCode: codes.Unauthenticated,
		},
		{
			name:       "bootstrap allowed for specific method",
			metadata:   map[string]string{},
			method:     "/tenant.v1.TenantService/Bootstrap",
			wantErr:    false,
		},
		{
			name:       "missing metadata",
			metadata:   nil,
			method:     "/some.Service/Method",
			wantErr:    true,
			wantErrCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.metadata != nil {
				md := metadata.New(tt.metadata)
				ctx = metadata.NewIncomingContext(ctx, md)
			}

			interceptor := TenantInterceptor()

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return nil, nil
			}

			info := &grpc.UnaryServerInfo{
				FullMethod: tt.method,
			}

			_, err := interceptor(ctx, nil, info, handler)

			if (err != nil) != tt.wantErr {
				t.Errorf("interceptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				st, ok := status.FromError(err)
				if !ok {
					t.Errorf("error is not a status error")
					return
				}
				if st.Code() != tt.wantErrCode {
					t.Errorf("error code = %v, wantErrCode %v", st.Code(), tt.wantErrCode)
				}
			}
		})
	}
}

func TestStreamTenantInterceptor(t *testing.T) {
	tests := []struct {
		name       string
		metadata   map[string]string
		method     string
		wantErr    bool
		wantErrCode codes.Code
	}{
		{
			name:       "valid tenant",
			metadata:   map[string]string{"x-tenant-id": "tenant-123"},
			method:     "/some.Service/Method",
			wantErr:    false,
		},
		{
			name:       "missing tenant id",
			metadata:   map[string]string{},
			method:     "/some.Service/Method",
			wantErr:    true,
			wantErrCode: codes.Unauthenticated,
		},
		{
			name:       "bootstrap allowed for specific method",
			metadata:   map[string]string{},
			method:     "/tenant.v1.TenantService/Bootstrap",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.metadata != nil {
				md := metadata.New(tt.metadata)
				ctx = metadata.NewIncomingContext(ctx, md)
			}

			interceptor := StreamTenantInterceptor()

			handler := func(srv interface{}, stream grpc.ServerStream) error {
				return nil
			}

			info := &grpc.StreamServerInfo{
				FullMethod: tt.method,
			}

			ss := &mockServerStream{
				ctx: ctx,
			}

			err := interceptor(nil, ss, info, handler)

			if (err != nil) != tt.wantErr {
				t.Errorf("interceptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				st, ok := status.FromError(err)
				if !ok {
					t.Errorf("error is not a status error")
					return
				}
				if st.Code() != tt.wantErrCode {
					t.Errorf("error code = %v, wantErrCode %v", st.Code(), tt.wantErrCode)
				}
			}
		})
	}
}
