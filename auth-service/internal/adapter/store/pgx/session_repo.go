package pgx

import (
	"auth-service/internal/adapter/store/pgx/sqlc"
	"auth-service/internal/domain"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
)

type SessionRepository struct {
	q *sqlc.Queries
}

func NewSessionRepository(q *sqlc.Queries) *SessionRepository {
	return &SessionRepository{
		q: q,
	}
}

func (repo *SessionRepository) Create(
	ctx context.Context, session domain.Session, token domain.RefreshToken,
) error {
	if err := repo.q.CreateSession(ctx, sqlc.CreateSessionParams{
		TokenHash:        token.Hash(),
		TokenExpiresAt:   pgtype.Timestamptz{Time: token.ExpiresAt, Valid: true},
		UserID:           pgtype.UUID{Bytes: session.UserID, Valid: true},
		SessionExpiresAt: pgtype.Timestamptz{Time: session.ExpiresAt, Valid: true},
	}); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	return nil
}

func (repo *SessionRepository) CreateRefreshToken(ctx context.Context, session domain.Session, token domain.RefreshToken) error {
	if err := repo.q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		SessionID: session.ID,
		TokenHash: token.Hash(),
		ExpiresAt: pgtype.Timestamptz{Time: token.ExpiresAt, Valid: true},
	}); err != nil {
		return err
	}

	return nil
}

func (repo *SessionRepository) GetRefreshToken(ctx context.Context, tokenHash []byte) (domain.RefreshToken, error) {
	token, err := repo.q.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.RefreshToken{}, domain.ErrTokenNotFound
		}

		return domain.RefreshToken{}, err
	}

	return domain.RefreshToken{
		ExpiresAt:  token.ExpiresAt.Time,
		ConsumedAt: token.ConsumedAt.Time,
	}, nil
}

func (repo *SessionRepository) ConsumeToken(
	ctx context.Context, tokenHash []byte,
) error {
	if err := repo.q.ConsumeToken(ctx, tokenHash); err != nil {
		return err
	}

	return nil
}

func (repo *SessionRepository) GetByTokenForUpdate(ctx context.Context, tokenHash []byte) (domain.Session, error) {
	session, err := repo.q.GetSessionByTokenForUpdate(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Session{}, domain.ErrSessionNotFound
		}

		return domain.Session{}, err
	}

	return domain.Session{
		ID:        session.ID,
		UserID:    session.UserID.Bytes,
		ExpiresAt: session.ExpiresAt.Time,
		RevokedAt: session.RevokedAt.Time,
	}, nil
}

func (repo *SessionRepository) Revoke(ctx context.Context, id int64) error {
	if err := repo.q.RevokeSession(ctx, id); err != nil {
		return err
	}

	return nil
}

func (repo *SessionRepository) RevokeByToken(ctx context.Context, tokenHash []byte) error {
	affected, err := repo.q.RevokeSessionByToken(ctx, tokenHash)
	if err != nil {
		return err
	}

	if affected == 0 {
		return domain.ErrSessionNotFound
	}

	return nil
}
