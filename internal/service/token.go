package service

import (
	"time"

	"GoAuth/internal/model"

	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenClaims struct {
	Role string `json:"role"`
	SID  string `json:"sid"`
	jwt.RegisteredClaims
}

func (s *AuthService) issueAccessToken(userID, sessionID string, role model.Role, now time.Time) (string, time.Time, error) {
	exp := now.Add(s.cfg.AccessTokenTTL)
	claims := AccessTokenClaims{
		Role: string(role),
		SID:  sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := t.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func (s *AuthService) parseAccessToken(token string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}
