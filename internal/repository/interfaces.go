package repository

import (
	"context"
	"time"

	"GoAuth/internal/model"

	"github.com/google/uuid"
)

type LoginMetadata struct {
	UserID    uuid.UUID
	At        time.Time
	IPAddress string
	UserAgent string
	Device    string
}

type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	MarkEmailVerified(ctx context.Context, userID uuid.UUID, verifiedAt time.Time) error
	UpdatePasswordHash(ctx context.Context, userID uuid.UUID, passwordHash string) error
	IsEmailTaken(ctx context.Context, email string) (bool, error)
}

type SessionRepository interface {
	Create(ctx context.Context, session *model.Session) error
	CreateWithLoginMetadata(ctx context.Context, session *model.Session, metadata LoginMetadata) error
	GetByAccessTokenHash(ctx context.Context, accessTokenHash string) (*model.Session, error)
	GetByRefreshTokenHash(ctx context.Context, refreshTokenHash string) (*model.Session, error)
	GetByID(ctx context.Context, sessionID uuid.UUID) (*model.Session, error)
	ListActiveByUserID(ctx context.Context, userID uuid.UUID) ([]model.Session, error)
	RevokeByID(ctx context.Context, sessionID uuid.UUID) error
	RevokeByIDForUser(ctx context.Context, sessionID, userID uuid.UUID) (bool, error)
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
}

type OTPRepository interface {
	SetEmailVerificationOTP(ctx context.Context, normalizedEmail, otp string, ttl time.Duration) error
	GetEmailVerificationOTP(ctx context.Context, normalizedEmail string) (value string, found bool, err error)
	DeleteEmailVerificationOTP(ctx context.Context, normalizedEmail string) error

	SetForgotPasswordOTP(ctx context.Context, normalizedEmail, otp string, ttl time.Duration) error
	GetForgotPasswordOTP(ctx context.Context, normalizedEmail string) (value string, found bool, err error)
	DeleteForgotPasswordOTP(ctx context.Context, normalizedEmail string) error

	SetPasswordResetTempToken(ctx context.Context, tokenHash, normalizedEmail string, ttl time.Duration) error
	GetPasswordResetTempTokenEmail(ctx context.Context, tokenHash string) (email string, found bool, err error)
	DeletePasswordResetTempToken(ctx context.Context, tokenHash string) error
}
