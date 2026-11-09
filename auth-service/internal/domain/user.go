package domain

import (
	"errors"
	"fmt"
	"regexp"
	"uuid"

	"github.com/alexedwards/argon2id"
)

type Email string

var emailRegexp = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

var ErrInvalidEmail = errors.New("invalid email")

func NewEmail(email string) (Email, error) {
	if !emailRegexp.MatchString(email) {
		return "", ErrInvalidEmail
	}

	return Email(email), nil
}

type User struct {
	ID           uuid.UUID
	Email        Email
	passwordHash string
}

var (
	ErrPasswordConfirmationMismatch = errors.New("password and repeat password do not match")
	ErrPasswordMismatch             = errors.New("password does not match stored hash")
)

func NewUser(
	id uuid.UUID, email Email,
	password, repeatPassword string,
) (User, error) {
	if password != repeatPassword {
		return User{}, ErrPasswordConfirmationMismatch
	}

	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return User{}, fmt.Errorf("create hash: %w", err)
	}

	return User{
		ID:           id,
		Email:        email,
		passwordHash: hash,
	}, nil
}

func RestoreUser(id uuid.UUID, email string, passwordHash string) User {
	return User{
		ID:           id,
		Email:        Email(email),
		passwordHash: passwordHash,
	}
}

func (u User) PasswordHash() string {
	return u.passwordHash
}

func (u User) VerifyPassword(password string) error {
	match, err := argon2id.ComparePasswordAndHash(password, u.passwordHash)
	if err != nil {
		return fmt.Errorf("compare password and hash: %w", err)
	}

	if !match {
		return ErrPasswordMismatch
	}

	return nil
}

var (
	ErrUserNotFound = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)
