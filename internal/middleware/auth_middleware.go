package middleware

import (
	"net/http"
	"strings"

	apperrors "GoAuth/internal/errors"
	"GoAuth/internal/model"
	"GoAuth/internal/repository"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthMiddleware struct {
	jwtSecret   string
	sessionRepo repository.SessionRepository
}

func NewAuthMiddleware(jwtSecret string, sessionRepo repository.SessionRepository) *AuthMiddleware {
	return &AuthMiddleware{jwtSecret: jwtSecret, sessionRepo: sessionRepo}
}

func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
		if token == "" || token == c.GetHeader("Authorization") {
			apperrors.Write(c, apperrors.ErrUnauthorized)
			return
		}

		claims := &accessClaims{}
		parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
			return []byte(m.jwtSecret), nil
		})
		if err != nil || !parsed.Valid {
			apperrors.Write(c, apperrors.ErrUnauthorized)
			return
		}
		if strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.SID) == "" {
			apperrors.Write(c, apperrors.ErrUnauthorized)
			return
		}

		session, err := m.sessionRepo.GetByAccessTokenHash(c.Request.Context(), hashToken(token))
		if err != nil {
			apperrors.Write(c, apperrors.ErrUnauthorized)
			return
		}
		if session.IsRevoked || session.AccessExpired(nowUTC()) || session.ID.String() != claims.SID {
			apperrors.Write(c, apperrors.ErrUnauthorized)
			return
		}

		role := model.Role(claims.Role)
		if !role.IsValid() {
			apperrors.Write(c, apperrors.ErrUnauthorized)
			return
		}

		c.Set("user_id", claims.Subject)
		c.Set("role", string(role))
		c.Set("session_id", claims.SID)
		c.Next()
	}
}

type accessClaims struct {
	Role string `json:"role"`
	SID  string `json:"sid"`
	jwt.RegisteredClaims
}

func UnauthorizedJSON(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error": gin.H{
			"code":    apperrors.ErrUnauthorized.Code,
			"message": apperrors.ErrUnauthorized.Message,
		},
	})
}
