package service

import (
	"time"

	"GoAuth/internal/model"

	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenClaims struct {
	Role  string `json:"role"`
	Email string `json:"email"`
	SID   string `json:"sid"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(jwtSecret, userID, email, sessionID string, role model.Role, ttl time.Duration, now time.Time) (string, time.Time, error) {
	exp := now.Add(ttl)
	claims := AccessTokenClaims{
		Role:  string(role),
		Email: email,
		SID:   sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := t.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func ParseAccessToken(jwtSecret, token string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		return []byte(jwtSecret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

func (s *AuthService) issueAccessToken(userID, email, sessionID string, role model.Role, now time.Time) (string, time.Time, error) {
	return GenerateAccessToken(s.cfg.JWTSecret, userID, email, sessionID, role, s.cfg.AccessTokenTTL, now)
}

func (s *AuthService) parseAccessToken(token string) (*AccessTokenClaims, error) {
	return ParseAccessToken(s.cfg.JWTSecret, token)
}
