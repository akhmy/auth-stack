package usecase

import "context"

type AccessTokenClaims struct {
	ID string
}

type contextKey int

const (
	loggerKey contextKey = iota
	claimsKey
)

func ContextWithClaims(ctx context.Context, claims AccessTokenClaims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

func ContextClaims(ctx context.Context) AccessTokenClaims {
	return ctx.Value(claimsKey).(AccessTokenClaims)
}

type Logger interface {
	Warn(msg string, args ...any)
}

type NopLogger struct{}

func (n *NopLogger) Warn(_ string, _ ...any) {}

func ContextWithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func ContextLogger(ctx context.Context) Logger {
	if ctx == nil {
		return &NopLogger{}
	}

	logger, ok := ctx.Value(loggerKey).(Logger)
	if !ok || logger == nil {
		return &NopLogger{}
	}

	return logger
}
