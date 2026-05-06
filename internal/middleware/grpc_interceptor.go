package middleware

import (
	"context"
	"strings"

	"github.com/samaasi/go-waf/internal/analysis"
	"github.com/samaasi/go-waf/internal/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GrpcInterceptor provides WAF inspection for gRPC services.
type GrpcInterceptor struct {
	pipeline *analysis.Pipeline
}

func NewGrpcInterceptor(pipeline *analysis.Pipeline) *GrpcInterceptor {
	return &GrpcInterceptor{pipeline: pipeline}
}

// UnaryInterceptor returns a gRPC unary interceptor for WAF inspection.
func (i *GrpcInterceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		
		// Map gRPC context to WAF Request
		wafReq := &domain.WafRequest{
			ID:      "grpc-" + info.FullMethod, // Better to use UUID if possible
			Method:  "POST",
			Path:    info.FullMethod,
			Headers: make(map[string][]string),
			Protocol: "gRPC",
		}

		// Extract metadata to headers
		for k, v := range md {
			wafReq.Headers[strings.ToLower(k)] = v
		}

		// Perform inspection
		verdict, events := i.pipeline.Inspect(ctx, wafReq)
		if verdict == domain.ActionBlock {
			i.pipeline.FinishTransaction(wafReq, events)
			return nil, status.Errorf(codes.PermissionDenied, "Request blocked by WAF policy")
		}

		// Proceed to handler
		resp, err := handler(ctx, req)
		
		// Post-inspection (DLP)
		// Note: Inspecting the response object requires serialization which might be expensive.
		// For now, we mainly focus on request-side hardening.
		
		i.pipeline.FinishTransaction(wafReq, events)
		return resp, err
	}
}
