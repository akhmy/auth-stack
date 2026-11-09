package interceptor

import (
	"auth-service/internal/usecase"
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func JWTAuth(
	parse func(string) (usecase.AccessTokenClaims, error),
	methods ...string,
) grpc.UnaryServerInterceptor {
	methodMap := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		methodMap[method] = struct{}{}
	}

	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if _, ok := methodMap[info.FullMethod]; !ok {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(
				codes.InvalidArgument,
				"metadata not found in incoming context",
			)
		}

		authHeader := md.Get("authorization")
		if len(authHeader) == 0 {
			return nil, status.Errorf(
				codes.InvalidArgument,
				"authorization header not found in incoming context",
			)
		}

		scheme, token, found := strings.Cut(authHeader[0], " ")
		if !found {
			return nil, status.Errorf(
				codes.InvalidArgument,
				"invalid authorization header",
			)
		}

		if !strings.EqualFold(scheme, "bearer") {
			return nil, status.Errorf(
				codes.InvalidArgument,
				"invalid authorization scheme",
			)
		}

		claims, err := parse(token)
		if err != nil {
			return nil, status.Errorf(
				codes.InvalidArgument,
				"invalid authorization token",
			)
		}

		return handler(usecase.ContextWithClaims(ctx, claims), req)
	}
}
