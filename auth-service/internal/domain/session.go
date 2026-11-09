package domain

import (
	"errors"
	"time"
	"uuid"
)

type Session struct {
	ID        int64
	UserID    uuid.UUID
	ExpiresAt time.Time
	RevokedAt time.Time
}

func NewSession(userID uuid.UUID, expiresAt time.Time) (Session, error) {
	if expiresAt.Before(time.Now()) {
		return Session{}, ErrSessionExpired
	}

	return Session{
		UserID:    userID,
		ExpiresAt: expiresAt,
	}, nil
}

var (
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionRevoked  = errors.New("session revoked")
	ErrSessionNotFound = errors.New("session not found")
)
