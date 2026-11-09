package auth

import (
	"auth-service/internal/usecase"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTTokenIssuer struct {
	name   string
	secret []byte
}

func NewJWTTokenIssuer(name string, secret []byte) *JWTTokenIssuer {
	return &JWTTokenIssuer{
		name:   name,
		secret: secret,
	}
}

func (iss *JWTTokenIssuer) Issue(claims usecase.AccessTokenClaims, ttl time.Duration) (string, error) {
	issAt := time.Now()
	expAt := issAt.Add(ttl)

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Subject:   claims.ID,
			Issuer:    iss.name,
			ExpiresAt: jwt.NewNumericDate(expAt),
			IssuedAt:  jwt.NewNumericDate(issAt),
		},
	)

	signed, err := token.SignedString(iss.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

func (iss *JWTTokenIssuer) Parse(token string) (usecase.AccessTokenClaims, error) {
	claims := &jwt.RegisteredClaims{}

	_, err := jwt.ParseWithClaims(
		token,
		claims,
		func(_ *jwt.Token) (any, error) {
			return iss.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(iss.name),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return usecase.AccessTokenClaims{}, err
	}

	return usecase.AccessTokenClaims{
		ID: claims.Subject,
	}, nil
}
