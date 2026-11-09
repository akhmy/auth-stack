package main

import (
	"auth-service/internal/adapter/auth"
	"auth-service/internal/adapter/handler"
	pgxstore "auth-service/internal/adapter/store/pgx"
	"auth-service/internal/adapter/store/pgx/sqlc"
	"auth-service/internal/pkg/config"
	pkggrpc "auth-service/internal/pkg/grpc"
	"auth-service/internal/pkg/interceptor"
	pkgpgx "auth-service/internal/pkg/pgx"
	"auth-service/internal/usecase"
	authv1 "auth-service/proto/gen/auth/v1"
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.ParseEnv()
	if err != nil {
		logger.Error("failed to parse env", "error", err)
		return
	}

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		logger.Error("failed to listen", "error", err)
		return
	}

	defer func() {
		if err := lis.Close(); err != nil {
			logger.Info("failed to close listener", "error", err)
		}
	}()

	jwtSecret, err := os.ReadFile(cfg.JWTSecretFile)
	if err != nil {
		logger.Error("failed to read JWT secret file", "error", err)
		return
	}

	dbPasswordBytes, err := os.ReadFile(cfg.DB.PasswordFile)
	if err != nil {
		logger.Error("failed to read DB password file", "error", err)
		return
	}

	poolCtx, poolCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer poolCancel()

	pool, err := pgxpool.New(
		poolCtx,
		pkgpgx.BuildConnString(
			cfg.DB.User,
			string(dbPasswordBytes),
			cfg.DB.Host,
			cfg.DB.Port,
			cfg.DB.Name,
			cfg.DB.Options...,
		),
	)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return
	}
	defer pool.Close()

	pingCtx, pingCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer pingCancel()

	if err := pool.Ping(pingCtx); err != nil {
		logger.Error("failed to ping database", "error", err)
		return
	}

	q := sqlc.New(pool)

	tokens := auth.NewJWTTokenIssuer("auth-service", jwtSecret)

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptor.Recover(),
			interceptor.Logger(logger),
			interceptor.JWTAuth(tokens.Parse),
		),
	)

	authv1.RegisterAuthServiceServer(srv, handler.NewAuthServiceServer(
		logger,
		usecase.NewAuthService(
			pgxstore.NewTxManager(pool),
			pgxstore.NewUserRepository(q),
			pgxstore.NewSessionRepository(q),
			tokens,
			cfg.AccessTokenTTL,
			cfg.RefreshTokenTTL,
			cfg.SessionTTL,
		),
	))

	errCh := make(chan error, 1)

	sigCtx, sigCancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer sigCancel()

	go func() {
		errCh <- srv.Serve(lis)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("server error", "error", err)
			return
		}
	case <-sigCtx.Done():
		logger.Info("shutting down server")

		shutdownCtx, shutdownCancel := context.WithTimeout(
			context.Background(), 10*time.Second,
		)
		defer shutdownCancel()

		if pkggrpc.GracefulStop(shutdownCtx, srv) {
			logger.Info("server stopped gracefully")
		} else {
			logger.Info("server stopped unexpectedly")
		}

		return
	}
}
