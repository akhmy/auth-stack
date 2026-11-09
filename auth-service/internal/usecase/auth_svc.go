package usecase

import (
	"auth-service/internal/domain"
	"context"
	"fmt"
	"time"
	"uuid"
)

type AuthService struct {
	tm TxManager

	users    UserRepository
	sessions SessionRepository
	tokens   TokenIssuer

	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	sessionTTL      time.Duration
}

func NewAuthService(
	tm TxManager,

	users UserRepository,
	sessions SessionRepository,
	tokens TokenIssuer,

	accessTokenTTL, refreshTokenTTL, sessionTTL time.Duration,
) *AuthService {
	return &AuthService{
		tm: tm,

		users:    users,
		sessions: sessions,
		tokens:   tokens,

		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		sessionTTL:      sessionTTL,
	}
}

type LogInInput struct {
	Email    string
	Password string
}

type LogInOutput struct {
	AccessToken     string
	AccessTokenTTL  time.Duration
	RefreshToken    string
	RefreshTokenTTL time.Duration
}

func (svc *AuthService) LogIn(ctx context.Context, in LogInInput) (LogInOutput, error) {
	email, err := domain.NewEmail(in.Email)
	if err != nil {
		return LogInOutput{}, fmt.Errorf("create email value object: %w", err)
	}

	user, err := svc.users.GetByEmail(ctx, email)
	if err != nil {
		return LogInOutput{}, fmt.Errorf("get user by email: %w", err)
	}

	if err := user.VerifyPassword(in.Password); err != nil {
		return LogInOutput{}, fmt.Errorf("verify password: %w", err)
	}

	return logIn(ctx, user, svc.accessTokenTTL, svc.refreshTokenTTL, svc.sessionTTL, svc.tokens, svc.sessions)
}

func (svc *AuthService) LogOut(ctx context.Context, token string) error {
	if err := svc.sessions.RevokeByToken(ctx, domain.HashToken(token)); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

type SignUpInput struct {
	ID             uuid.UUID
	Email          string
	Password       string
	RepeatPassword string
}

func (svc *AuthService) SignUp(ctx context.Context, in SignUpInput) (LogInOutput, error) {
	email, err := domain.NewEmail(in.Email)
	if err != nil {
		return LogInOutput{}, fmt.Errorf("create email value object: %w", err)
	}

	user, err := domain.NewUser(in.ID, email, in.Password, in.RepeatPassword)
	if err != nil {
		return LogInOutput{}, fmt.Errorf("create user: %w", err)
	}

	var out LogInOutput

	if err := svc.tm.WithinTx(ctx, func(users UserRepository, sessions SessionRepository) error {
		if err := users.Create(ctx, user); err != nil {
			return fmt.Errorf("save user: %w", err)
		}

		out, err = logIn(ctx, user, svc.accessTokenTTL, svc.refreshTokenTTL, svc.sessionTTL, svc.tokens, sessions)
		if err != nil {
			return fmt.Errorf("log in: %w", err)
		}

		return nil
	}); err != nil {
		return LogInOutput{}, err
	}

	return out, nil
}

func logIn(
	ctx context.Context,
	user domain.User,
	accessTokenTTL,
	refreshTokenTTL,
	sessionTTL time.Duration,
	tokens TokenIssuer,
	sessions SessionRepository,
) (LogInOutput, error) {
	accessTTL := min(accessTokenTTL, sessionTTL)

	access, err := tokens.Issue(AccessTokenClaims{ID: user.ID.String()}, accessTTL)
	if err != nil {
		return LogInOutput{}, fmt.Errorf("issue access token: %w", err)
	}

	refreshTTL := min(refreshTokenTTL, sessionTTL)
	now := time.Now()

	refresh, refreshString, err := domain.NewRefreshToken(now.Add(refreshTTL))
	if err != nil {
		return LogInOutput{}, fmt.Errorf("create refresh token: %w", err)
	}

	session, err := domain.NewSession(user.ID, now.Add(sessionTTL))
	if err != nil {
		return LogInOutput{}, fmt.Errorf("create session: %w", err)
	}

	if err := sessions.Create(ctx, session, refresh); err != nil {
		return LogInOutput{}, fmt.Errorf("save session: %w", err)
	}

	return LogInOutput{
		AccessToken:     access,
		AccessTokenTTL:  accessTTL,
		RefreshToken:    refreshString,
		RefreshTokenTTL: refreshTTL,
	}, nil
}

func (svc *AuthService) Refresh(ctx context.Context, oldToken string) (LogInOutput, error) {
	var (
		accessToken  string
		refreshToken string

		accessTokenTTL  time.Duration
		refreshTokenTTL time.Duration

		reuseDetected bool
	)

	if err := svc.tm.WithinTx(ctx, func(
		users UserRepository,
		sessions SessionRepository,
	) error {
		oldHash := domain.HashToken(oldToken)

		session, err := sessions.GetByTokenForUpdate(ctx, oldHash)
		if err != nil {
			return fmt.Errorf("get session by old token: %w", err)
		}

		now := time.Now()

		if now.After(session.ExpiresAt) {
			return domain.ErrSessionExpired
		}

		if !session.RevokedAt.IsZero() {
			return domain.ErrSessionRevoked
		}

		refresh, err := sessions.GetRefreshToken(ctx, oldHash)
		if err != nil {
			return fmt.Errorf("get refresh token: %w", err)
		}

		if !refresh.ConsumedAt.IsZero() {
			if err := sessions.Revoke(ctx, session.ID); err != nil {
				return fmt.Errorf("revoke session with consumed token: %w", err)
			}

			reuseDetected = true
			return nil
		}

		if time.Now().After(refresh.ExpiresAt) {
			return domain.ErrTokenExpired
		}

		if err := sessions.ConsumeToken(ctx, oldHash); err != nil {
			return fmt.Errorf("consume old token: %w", err)
		}

		refreshTokenTTL = min(svc.refreshTokenTTL, time.Until(session.ExpiresAt))

		refresh, refreshToken, err = domain.NewRefreshToken(time.Now().Add(refreshTokenTTL))
		if err != nil {
			return fmt.Errorf("create refresh token: %w", err)
		}

		if err := sessions.CreateRefreshToken(ctx, session, refresh); err != nil {
			return fmt.Errorf("save refresh token: %w", err)
		}

		accessTokenTTL = min(svc.accessTokenTTL, time.Until(session.ExpiresAt))

		accessToken, err = svc.tokens.Issue(AccessTokenClaims{ID: session.UserID.String()}, accessTokenTTL)
		if err != nil {
			return fmt.Errorf("issue access token: %w", err)
		}

		return nil
	}); err != nil {
		return LogInOutput{}, err
	}

	if reuseDetected {
		return LogInOutput{}, domain.ErrTokenAlreadyConsumed
	}

	return LogInOutput{
		AccessToken:     accessToken,
		AccessTokenTTL:  accessTokenTTL,
		RefreshToken:    refreshToken,
		RefreshTokenTTL: refreshTokenTTL,
	}, nil
}
