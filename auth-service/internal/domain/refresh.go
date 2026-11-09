package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

func HashToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

type RefreshToken struct {
	hash       []byte
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

func NewRefreshToken(expiresAt time.Time) (RefreshToken, string, error) {
	random := make([]byte, 32)

	if _, err := rand.Read(random); err != nil {
		return RefreshToken{}, "", err
	}

	token := make([]byte, base64.RawURLEncoding.EncodedLen(len(random)))

	base64.RawURLEncoding.Encode(token, random)

	return RefreshToken{
		hash:      HashToken(string(token)),
		ExpiresAt: expiresAt,
	}, string(token), nil
}

func (t RefreshToken) Hash() []byte {
	return t.hash
}

var (
	ErrTokenNotFound = errors.New("refresh token not found")
	ErrTokenExpired  = errors.New("refresh token expired")
	ErrTokenAlreadyConsumed = errors.New("refresh token already consumed")
)
