package handler

import (
	"auth-service/internal/domain"
	"auth-service/internal/usecase"
	authv1 "auth-service/proto/gen/auth/v1"
	"context"
	"errors"
	"log/slog"
	"uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type AuthService interface {
	LogIn(ctx context.Context, in usecase.LogInInput) (usecase.LogInOutput, error)
	LogOut(ctx context.Context, refreshToken string) error
	SignUp(ctx context.Context, in usecase.SignUpInput) (usecase.LogInOutput, error)
	Refresh(ctx context.Context, refreshToken string) (usecase.LogInOutput, error)
}

type AuthServiceServer struct {
	svc AuthService

	logger *slog.Logger
	authv1.UnimplementedAuthServiceServer
}

func NewAuthServiceServer(logger *slog.Logger, svc AuthService) *AuthServiceServer {
	return &AuthServiceServer{
		svc:    svc,
		logger: logger,
	}
}

func (srv *AuthServiceServer) LogIn(ctx context.Context, req *authv1.LogInRequest) (*authv1.LogInResponse, error) {
	out, err := srv.svc.LogIn(ctx, usecase.LogInInput{
		Email:    req.GetEmail(),
		Password: req.GetPassword(),
	})
	if err != nil {
		srv.logger.Error("failed to log in", "error", err)

		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, status.Error(
				codes.NotFound,
				domain.ErrUserNotFound.Error(),
			)
		}

		return nil, err
	}

	return &authv1.LogInResponse{
		AccessToken:     out.AccessToken,
		AccessTokenTtl:  int64(out.AccessTokenTTL.Seconds()),
		RefreshToken:    out.RefreshToken,
		RefreshTokenTtl: int64(out.RefreshTokenTTL.Seconds()),
	}, nil
}

func (srv *AuthServiceServer) LogOut(ctx context.Context, request *authv1.LogOutRequest) (*emptypb.Empty, error) {
	if err := srv.svc.LogOut(ctx, request.GetRefreshToken()); err != nil {
		srv.logger.Info("failed to log out", "error", err)

		if errors.Is(err, domain.ErrSessionNotFound) {
			return &emptypb.Empty{}, status.Error(
				codes.NotFound,
				domain.ErrSessionNotFound.Error(),
			)
		}
	}

	return &emptypb.Empty{}, nil
}

func (srv *AuthServiceServer) SignUp(ctx context.Context, request *authv1.SignUpRequest) (*authv1.LogInResponse, error) {
	id, err := uuid.Parse(request.GetId())
	if err != nil {
		srv.logger.Error("failed to parse id", "error", err)

		return nil, status.Error(
			codes.Internal,
			"internal server error",
		)
	}

	out, err := srv.svc.SignUp(ctx, usecase.SignUpInput{
		ID:             id,
		Email:          request.GetEmail(),
		Password:       request.GetPassword(),
		RepeatPassword: request.GetRepeatPassword(),
	})
	if err != nil {
		srv.logger.Error("failed to sign up", "error", err)

		if errors.Is(err, domain.ErrUserAlreadyExists) {
			return nil, status.Error(
				codes.AlreadyExists,
				domain.ErrUserAlreadyExists.Error(),
			)
		}

		return nil, err
	}

	return &authv1.LogInResponse{
		AccessToken:     out.AccessToken,
		AccessTokenTtl:  int64(out.AccessTokenTTL.Seconds()),
		RefreshToken:    out.RefreshToken,
		RefreshTokenTtl: int64(out.RefreshTokenTTL.Seconds()),
	}, nil
}

func (srv *AuthServiceServer) Refresh(ctx context.Context, request *authv1.RefreshRequest) (*authv1.LogInResponse, error) {
	out, err := srv.svc.Refresh(ctx, request.GetRefreshToken())
	if err != nil {
		srv.logger.Error("failed to refresh", "error", err)

		if errors.Is(err, domain.ErrSessionNotFound) {
			return nil, status.Error(
				codes.NotFound,
				domain.ErrSessionNotFound.Error(),
			)
		}

		if errors.Is(err, domain.ErrSessionExpired) {
			return nil, status.Error(
				codes.Unauthenticated,
				domain.ErrSessionExpired.Error(),
			)
		}

		if errors.Is(err, domain.ErrSessionRevoked) {
			return nil, status.Error(
				codes.Unauthenticated,
				domain.ErrSessionRevoked.Error(),
			)
		}

		if errors.Is(err, domain.ErrTokenNotFound) ||
			errors.Is(err, domain.ErrTokenExpired) ||
			errors.Is(err, domain.ErrTokenAlreadyConsumed) {
			return nil, status.Error(
				codes.NotFound,
				domain.ErrTokenNotFound.Error(),
			)
		}

		return nil, err
	}

	return &authv1.LogInResponse{
		AccessToken:     out.AccessToken,
		AccessTokenTtl:  int64(out.AccessTokenTTL.Seconds()),
		RefreshToken:    out.RefreshToken,
		RefreshTokenTtl: int64(out.RefreshTokenTTL.Seconds()),
	}, nil
}
