package service

import (
	"context"
	"time"

	"GoAuth/internal/model"
	"GoAuth/internal/repository"
)

type EmailSender interface {
	SendSignupEmail(to, otp string, expiryMinutes int) error
	SendVerifyEmail(to string, loginLink string) error
	SendLoginNotification(to, ip, device string) error
	SendLogoutNotification(to, reason string) error
	SendPasswordResetEmail(to, otp string, expiryMinutes int) error
	SendPasswordChangedEmail(to, loginLink string) error
}

type AuthConfig struct {
	JWTSecret            string
	BcryptCost           int
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
	EmailVerificationTTL time.Duration
	ForgotPasswordOTPTTL time.Duration
	ResetTempTokenTTL    time.Duration
}

type RequestMeta struct {
	IPAddress string
	UserAgent string
	Device    string
}

type AuthService struct {
	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
	otpRepo     repository.OTPRepository
	emailSender EmailSender
	cfg         AuthConfig
	logger      Logger
}

type Logger interface {
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
}

type AuthPrincipal struct {
	UserID    string
	Role      model.Role
	SessionID string
}
