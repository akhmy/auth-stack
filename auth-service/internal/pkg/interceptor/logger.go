package interceptor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
)

func Logger(l *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		logger := l.With(
			"method", info.FullMethod,
		)

		logger.Info("request received")

		start := time.Now()

		defer func() {
			if r := recover(); r != nil {
				var msg string

				err, ok := r.(error)
				if !ok {
					msg = fmt.Sprintf("%v", r)
				} else {
					msg = err.Error()
				}

				logger.Error(
					"panic",
					"error", msg,
				)

				panic(r)
			}
		}()

		resp, err := handler(ctx, req)
		if err != nil {
			logger = logger.With("error", err)
		}

		logger.Info(
			"request processed",
			"duration", time.Since(start),
		)

		return resp, err
	}
}
