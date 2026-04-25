package model

import (
	"time"

	"github.com/google/uuid"
)

// User maps to the users table defined in the auth contract.
type User struct {
	ID                 uuid.UUID  `json:"id"`
	Email              string     `json:"email"`
	PasswordHash       string     `json:"-"`
	Role               Role       `json:"role"`
	IsActive           bool       `json:"is_active"`
	IsEmailVerified    bool       `json:"is_email_verified"`
	EmailVerifiedAt    *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP        *string    `json:"last_login_ip,omitempty"`
	LastLoginUserAgent *string    `json:"last_login_user_agent,omitempty"`
	LastLoginDevice    *string    `json:"last_login_device,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}
