package usecase

import (
	"auth-service/internal/domain"
	"context"
	"time"
)

type UserRepository interface {
	Create(ctx context.Context, u domain.User) error
	GetByEmail(ctx context.Context, email domain.Email) (domain.User, error)
}

type SessionRepository interface {
	Create(ctx context.Context, session domain.Session, token domain.RefreshToken) error
	GetByTokenForUpdate(ctx context.Context, tokenHash []byte) (domain.Session, error)
	Revoke(ctx context.Context, id int64) error
	RevokeByToken(ctx context.Context, tokenHash []byte) error

	CreateRefreshToken(ctx context.Context, session domain.Session, token domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash []byte) (domain.RefreshToken, error)
	ConsumeToken(ctx context.Context, tokenHash []byte) error
}

type TokenIssuer interface {
	Issue(claims AccessTokenClaims, ttl time.Duration) (string, error)
}

type Repositories interface {
	Users() UserRepository
	Sessions() SessionRepository
}

type TxManager interface {
	WithinTx(ctx context.Context, fn func(users UserRepository, sessions SessionRepository) error) error
}
