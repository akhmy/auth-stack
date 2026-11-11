//go:build integration

package usecase_test

import (
	"auth-service/internal/adapter/auth"
	"auth-service/internal/adapter/store/pgx/sqlc"
	"auth-service/internal/domain"
	"auth-service/internal/usecase"
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	pgxstore "auth-service/internal/adapter/store/pgx"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	os.Exit(testMainInner(m))
}

func testMainInner(m *testing.M) int {
	scripts, err := filepath.Glob("../../migrations/*.up.sql")
	if err != nil {
		log.Printf("failed to glob scripts: %v", err)
		return 1
	}

	runCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)

	pgContainer, err := postgres.Run(
		runCtx,
		"postgres:18.6",
		postgres.WithDatabase("auth_db"),
		postgres.WithUsername("auth_admin"),
		postgres.WithPassword("secret"),
		postgres.WithInitScripts(scripts...),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		log.Printf("failed to run postgres container: %v", err)
		cancel()

		return 1
	}

	cancel()

	defer func() {
		terminateCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		if err := pgContainer.Terminate(terminateCtx); err != nil {
			log.Printf("failed to terminate postgres container: %v", err)
		}

		cancel()
	}()

	connString, err := pgContainer.ConnectionString(context.Background())
	if err != nil {
		log.Printf("failed to construct connection string: %v", err)
		return 1
	}

	poolCtx, cancel := context.WithTimeout(context.Background(), time.Second*5)

	pool, err = pgxpool.New(poolCtx, connString)
	if err != nil {
		log.Printf("failed to connect to postgres: %v", err)
		cancel()

		return 1
	}

	cancel()

	defer pool.Close()

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	if err := pool.Ping(pingCtx); err != nil {
		log.Printf("failed to ping postgres: %v", err)
		cancel()

		return 1
	}

	cancel()

	return m.Run()
}

func TestAuthService_Integration(t *testing.T) {
	q := sqlc.New(pool)

	sessions := pgxstore.NewSessionRepository(q)

	svc := usecase.NewAuthService(
		pgxstore.NewTxManager(pool),
		pgxstore.NewUserRepository(q),
		pgxstore.NewSessionRepository(q),
		auth.NewJWTTokenIssuer("integration", []byte("integration")),
		time.Minute*15,
		time.Hour*720,
		time.Hour*2160,
	)

	t.Run("login nonexist", func(t *testing.T) {
		_, err := svc.LogIn(t.Context(), usecase.LogInInput{
			Email:    "akhmy@mail.com",
			Password: "secret",
		})
		require.Error(t, err, domain.ErrUserNotFound)
	})

	t.Run("rotation", func(t *testing.T) {
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			_, err := pool.Exec(cleanupCtx, "TRUNCATE TABLE refresh_tokens, sessions, users")

			cancel()

			require.NoError(t, err, "failed to cleanup db")
		})

		initial, err := svc.SignUp(t.Context(), usecase.SignUpInput{
			ID:             uuid.New(),
			Email:          "akhmy@mail.com",
			Password:       "secret",
			RepeatPassword: "secret",
		})
		require.NoError(t, err, "failed to sign up")

		refreshed, err := svc.Refresh(t.Context(), initial.RefreshToken)
		require.NoError(t, err, "failed to refresh")

		assert.NotEqual(t, initial.RefreshToken, refreshed.RefreshToken, "refreshed token should not be the same")

		oldToken, err := sessions.GetRefreshToken(t.Context(), domain.HashToken(initial.RefreshToken))
		require.NoError(t, err, "failed to get old refresh token")
		assert.NotZero(t, oldToken.ConsumedAt, "old refresh token should be consumed")

		byOldToken, err := sessions.GetByTokenForUpdate(t.Context(), domain.HashToken(initial.RefreshToken))
		require.NoError(t, err, "failed to get session by old refresh token")

		byNewToken, err := sessions.GetByTokenForUpdate(t.Context(), domain.HashToken(refreshed.RefreshToken))
		require.NoError(t, err, "failed to get session by new refresh token")

		assert.Equal(t, byOldToken, byNewToken, "both tokens should reference the same session")
	})

	t.Run("reuse", func(t *testing.T) {
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			_, err := pool.Exec(cleanupCtx, "TRUNCATE TABLE refresh_tokens, sessions, users")
			require.NoError(t, err, "failed to cleanup db")
			cancel()
		})

		initial, err := svc.SignUp(t.Context(), usecase.SignUpInput{
			ID:             uuid.New(),
			Email:          "akhmy@mail.com",
			Password:       "secret",
			RepeatPassword: "secret",
		})
		require.NoError(t, err, "failed to sign up")

		_, err = svc.Refresh(t.Context(), initial.RefreshToken)
		require.NoError(t, err, "failed to refresh")

		_, err = svc.Refresh(t.Context(), initial.RefreshToken)
		require.ErrorIs(t, err, domain.ErrTokenAlreadyConsumed)
	})
}
