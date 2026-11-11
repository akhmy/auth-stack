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
	os.Exit(mainInner())
}

func mainInner() int {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.ParseEnv()
	if err != nil {
		logger.Error("failed to parse env", "error", err)
		return 1
	}

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		logger.Error("failed to listen", "error", err)
		return 1
	}

	defer func() {
		if err := lis.Close(); err != nil {
			logger.Error("failed to close listener", "error", err)
		}
	}()

	jwtSecret, err := os.ReadFile(cfg.JWTSecretFile)
	if err != nil {
		logger.Error("failed to read JWT secret file", "error", err)
		return 1
	}

	dbPasswordBytes, err := os.ReadFile(cfg.DB.PasswordFile)
	if err != nil {
		logger.Error("failed to read DB password file", "error", err)
		return 1
	}

	poolCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
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

	cancel()

	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return 1
	}

	defer pool.Close()

	pingCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	err = pool.Ping(pingCtx)

	cancel()

	if err != nil {
		logger.Error("failed to ping database", "error", err)
		return 1
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

	sigCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		errCh <- srv.Serve(lis)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("server error", "error", err)
			return 1
		}
	case <-sigCtx.Done():
		logger.Info("shutting down server")

		shutdownCtx, shutdownCancel := context.WithTimeout(
			context.Background(), 10*time.Second,
		)
		defer shutdownCancel()

		if pkggrpc.GracefulStop(shutdownCtx, srv) {
			logger.Info("server stopped gracefully")
			return 0
		}

		logger.Info("server stopped unexpectedly")

		return 1
	}

	return 0
}
