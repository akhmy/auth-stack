package pgx

import (
	"auth-service/internal/adapter/store/pgx/sqlc"
	"auth-service/internal/usecase"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TxManager struct {
	pool *pgxpool.Pool
}

func NewTxManager(pool *pgxpool.Pool) *TxManager {
	return &TxManager{
		pool: pool,
	}
}

func (tm *TxManager) WithinTx(
	ctx context.Context,
	fn func(users usecase.UserRepository, sessions usecase.SessionRepository) error) error {
	logger := usecase.ContextLogger(ctx)

	tx, err := tm.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	defer func() {
		rollbackCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		if err := tx.Rollback(rollbackCtx); err != nil {
			logger.Warn("failed to rollback tx", "error", err)
		}
	}()

	q := sqlc.New(tx)

	if err := fn(NewUserRepository(q), NewSessionRepository(q)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}
