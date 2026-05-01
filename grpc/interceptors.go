package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"hostingmaster.io/hm-lib/tenants"
)

const (
	// TenantIDHeader is the gRPC metadata key for tenant ID.
	TenantIDHeader = "x-tenant-id"
)

// TenantInterceptor adds tenant ID from metadata to context.
// This is a unary server interceptor that extracts the tenant ID from
// gRPC metadata and stores it in the context for tenant isolation.
func TenantInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		// Extract tenant ID from headers
		tenantIDs := md.Get(TenantIDHeader)
		if len(tenantIDs) == 0 {
			// Bootstrap allowed only for specific methods
			if info.FullMethod == "/tenant.v1.TenantService/Bootstrap" {
				ctx = tenant.WithBootstrap(ctx)
			} else {
				return nil, status.Error(codes.Unauthenticated, "missing tenant id in metadata")
			}
		} else {
			ctx = tenant.WithTenant(ctx, tenantIDs[0])
		}

		return handler(ctx, req)
	}
}

// StreamTenantInterceptor adds tenant ID from metadata to context for stream RPCs.
func StreamTenantInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "missing metadata")
		}

		// Extract tenant ID from headers
		tenantIDs := md.Get(TenantIDHeader)
		if len(tenantIDs) == 0 {
			// Bootstrap allowed only for specific methods
			if info.FullMethod == "/tenant.v1.TenantService/Bootstrap" {
				ctx = tenant.WithBootstrap(ctx)
			} else {
				return status.Error(codes.Unauthenticated, "missing tenant id in metadata")
			}
		} else {
			ctx = tenant.WithTenant(ctx, tenantIDs[0])
		}

		// Create wrapped server stream with updated context
		wrappedStream := &tenantAwareServerStream{
			ServerStream: ss,
			ctx:         ctx,
		}

		return handler(srv, wrappedStream)
	}
}

// tenantAwareServerStream wraps ServerStream to provide context with tenant ID.
type tenantAwareServerStream struct {
	grpc.ServerStream

	ctx context.Context
}

// Context returns the updated context with tenant ID.
func (ss *tenantAwareServerStream) Context() context.Context {
	return ss.ctx
}
