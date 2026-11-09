package pgx

import (
	"auth-service/internal/adapter/store/pgx/sqlc"
	"auth-service/internal/domain"
	"context"
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type UserRepository struct {
	q *sqlc.Queries
}

func NewUserRepository(q *sqlc.Queries) *UserRepository {
	return &UserRepository{
		q: q,
	}
}

func (repo *UserRepository) Create(ctx context.Context, user domain.User) error {
	if err := repo.q.CreateUser(ctx, sqlc.CreateUserParams{
		ID:           pgtype.UUID{Bytes: user.ID, Valid: true},
		Email:        string(user.Email),
		PasswordHash: user.PasswordHash(),
	}); err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
			switch pgErr.Code {
			case pgerrcode.UniqueViolation:
				return domain.ErrUserAlreadyExists
			}
		}

		return err
	}

	return nil
}

func (repo *UserRepository) GetByEmail(ctx context.Context, email domain.Email) (domain.User, error) {
	user, err := repo.q.GetUserByEmail(ctx, string(email))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, domain.ErrUserNotFound
		}

		return domain.User{}, err
	}

	return domain.RestoreUser(
		user.ID.Bytes,
		user.Email,
		user.PasswordHash,
	), nil
}
