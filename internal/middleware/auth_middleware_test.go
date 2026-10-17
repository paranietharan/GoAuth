package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"GoAuth/internal/middleware"
	"GoAuth/internal/model"
	"GoAuth/internal/repository"
	"GoAuth/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type mockSessionRepo struct {
	repository.SessionRepository
	session *model.Session
	err     error
}

func (m *mockSessionRepo) GetByAccessTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.session, nil
}

type mockUserRepo struct {
	repository.UserRepository
	user *model.User
	err  error
}

func (m *mockUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

func TestAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtSecret := "test-secret-at-least-32-characters-long"

	userID := uuid.New()
	sessionID := uuid.New()
	email := "test@example.com"
	role := model.RoleUser

	validToken, _, err := service.GenerateAccessToken(jwtSecret, userID.String(), email, sessionID.String(), role, 15*time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	expiredToken, _, err := service.GenerateAccessToken(jwtSecret, userID.String(), email, sessionID.String(), role, 1*time.Minute, time.Now().UTC().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("failed to generate expired token: %v", err)
	}

	activeSession := &model.Session{
		ID:        sessionID,
		UserID:    userID,
		IsRevoked: false,
		AccessExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	revokedSession := &model.Session{
		ID:        sessionID,
		UserID:    userID,
		IsRevoked: true,
		AccessExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	activeUser := &model.User{
		ID:       userID,
		Email:    email,
		Role:     role,
		IsActive: true,
	}

	inactiveUser := &model.User{
		ID:       userID,
		Email:    email,
		Role:     role,
		IsActive: false,
	}

	tests := []struct {
		name           string
		authHeader     string
		session        *model.Session
		sessionErr     error
		user           *model.User
		userErr        error
		expectedStatus int
	}{
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed authorization header",
			authHeader:     "Basic 12345",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "expired access token",
			authHeader:     "Bearer " + expiredToken,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "session not found in db",
			authHeader:     "Bearer " + validToken,
			sessionErr:     errors.New("session not found"),
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "session revoked in db",
			authHeader:     "Bearer " + validToken,
			session:        revokedSession,
			user:           activeUser,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "inactive user returns 403 forbidden",
			authHeader:     "Bearer " + validToken,
			session:        activeSession,
			user:           inactiveUser,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "valid token and active user succeeds",
			authHeader:     "Bearer " + validToken,
			session:        activeSession,
			user:           activeUser,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sRepo := &mockSessionRepo{session: tt.session, err: tt.sessionErr}
			uRepo := &mockUserRepo{user: tt.user, err: tt.userErr}
			authMw := middleware.NewAuthMiddleware(jwtSecret, sRepo, uRepo)

			r := gin.New()
			r.GET("/protected", authMw.RequireAuth(), func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Fatalf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}
