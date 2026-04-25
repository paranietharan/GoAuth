package model

import (
	"time"

	"github.com/google/uuid"
)

// Session maps to the sessions table and tracks token lifecycle per device.
type Session struct {
	ID               uuid.UUID `json:"id"`
	UserID           uuid.UUID `json:"user_id"`
	AccessTokenHash  string    `json:"-"`
	RefreshTokenHash string    `json:"-"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	IsRevoked        bool      `json:"is_revoked"`
	IPAddress        *string   `json:"ip_address,omitempty"`
	UserAgent        *string   `json:"user_agent,omitempty"`
	Device           *string   `json:"device,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (s Session) AccessExpired(now time.Time) bool {
	return !s.AccessExpiresAt.After(now)
}

func (s Session) RefreshExpired(now time.Time) bool {
	return !s.RefreshExpiresAt.After(now)
}
