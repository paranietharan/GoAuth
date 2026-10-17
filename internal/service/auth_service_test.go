package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"GoAuth/internal/dto"
	apperrors "GoAuth/internal/errors"
	"GoAuth/internal/model"
	"GoAuth/internal/repository"
	"GoAuth/internal/service"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type mockUserRepo struct {
	repository.UserRepository
	users map[uuid.UUID]*model.User
}

func (m *mockUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	if u, ok := m.users[id]; ok {
		return u, nil
	}
	return nil, apperrors.ErrNotFound
}

func (m *mockUserRepo) UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	if u, ok := m.users[id]; ok {
		u.PasswordHash = hash
		return nil
	}
	return apperrors.ErrNotFound
}

type mockSessionRepo struct {
	repository.SessionRepository
	sessions           map[uuid.UUID]*model.Session
	byRefreshHash      map[string]*model.Session
	revokedFamilyIDs   []uuid.UUID
	revokedUserIDs     []uuid.UUID
	rotatedOldSessions []uuid.UUID
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{
		sessions:      make(map[uuid.UUID]*model.Session),
		byRefreshHash: make(map[string]*model.Session),
	}
}

func (m *mockSessionRepo) GetByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	if s, ok := m.byRefreshHash[hash]; ok {
		return s, nil
	}
	return nil, apperrors.ErrNotFound
}

func (m *mockSessionRepo) RevokeAllByFamilyID(ctx context.Context, familyID uuid.UUID) error {
	m.revokedFamilyIDs = append(m.revokedFamilyIDs, familyID)
	for _, s := range m.sessions {
		if s.FamilyID == familyID {
			s.IsRevoked = true
		}
	}
	return nil
}

func (m *mockSessionRepo) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	m.revokedUserIDs = append(m.revokedUserIDs, userID)
	for _, s := range m.sessions {
		if s.UserID == userID {
			s.IsRevoked = true
		}
	}
	return nil
}

func (m *mockSessionRepo) RotateSession(ctx context.Context, oldID uuid.UUID, newSession *model.Session) (bool, error) {
	m.rotatedOldSessions = append(m.rotatedOldSessions, oldID)
	if s, ok := m.sessions[oldID]; ok {
		s.IsRevoked = true
	}
	m.sessions[newSession.ID] = newSession
	m.byRefreshHash[newSession.RefreshTokenHash] = newSession
	return true, nil
}

type mockEmailSender struct {
	service.EmailSender
}

func (m *mockEmailSender) SendSignupEmail(to, otp string, expiryMinutes int) error { return nil }
func (m *mockEmailSender) SendVerifyEmail(to string, loginLink string) error         { return nil }
func (m *mockEmailSender) SendLoginNotification(to, ip, device string) error        { return nil }
func (m *mockEmailSender) SendLogoutNotification(to, reason string) error           { return nil }
func (m *mockEmailSender) SendPasswordResetEmail(to, otp string, expiryMinutes int) error {
	return nil
}
func (m *mockEmailSender) SendPasswordChangedEmail(to, loginLink string) error { return nil }

type testLogger struct{}

func (l *testLogger) InfoContext(ctx context.Context, msg string, args ...any)  {}
func (l *testLogger) WarnContext(ctx context.Context, msg string, args ...any)  {}
func (l *testLogger) ErrorContext(ctx context.Context, msg string, args ...any) {}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestRefreshTokenReuseDetection(t *testing.T) {
	userRepo := &mockUserRepo{users: make(map[uuid.UUID]*model.User)}
	sessionRepo := newMockSessionRepo()
	emailSender := &mockEmailSender{}

	authSvc := service.NewAuthService(
		userRepo,
		sessionRepo,
		nil,
		emailSender,
		service.AuthConfig{
			JWTSecret:       "test-secret-at-least-32-characters-long",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 30 * 24 * time.Hour,
		},
		&testLogger{},
	)

	userID := uuid.New()
	familyID := uuid.New()
	stolenRefreshToken := "stolen-already-rotated-refresh-token"
	stolenHash := hashToken(stolenRefreshToken)

	revokedSession := &model.Session{
		ID:               uuid.New(),
		UserID:           userID,
		FamilyID:         familyID,
		RefreshTokenHash: stolenHash,
		RefreshExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked:        true, // Already rotated/revoked
	}
	sessionRepo.sessions[revokedSession.ID] = revokedSession
	sessionRepo.byRefreshHash[stolenHash] = revokedSession

	// Attacker tries to use revoked token
	_, appErr := authSvc.RefreshSession(context.Background(), stolenRefreshToken, service.RequestMeta{})
	if appErr == nil {
		t.Fatal("expected error on revoked token reuse, got nil")
	}
	if appErr.Code != apperrors.ErrUnauthorized.Code {
		t.Fatalf("expected ErrUnauthorized, got: %s", appErr.Code)
	}

	// Verify that entire family was revoked!
	foundFamilyRevocation := false
	for _, fID := range sessionRepo.revokedFamilyIDs {
		if fID == familyID {
			foundFamilyRevocation = true
			break
		}
	}
	if !foundFamilyRevocation {
		t.Fatalf("expected family %s to be revoked on reuse detection", familyID)
	}
}

func TestRefreshTokenSuccessfulRotation(t *testing.T) {
	userID := uuid.New()
	user := &model.User{
		ID:       userID,
		Email:    "test@example.com",
		Role:     model.RoleUser,
		IsActive: true,
	}

	userRepo := &mockUserRepo{users: map[uuid.UUID]*model.User{userID: user}}
	sessionRepo := newMockSessionRepo()
	emailSender := &mockEmailSender{}

	authSvc := service.NewAuthService(
		userRepo,
		sessionRepo,
		nil,
		emailSender,
		service.AuthConfig{
			JWTSecret:       "test-secret-at-least-32-characters-long",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 30 * 24 * time.Hour,
		},
		&testLogger{},
	)

	validRefreshToken := "legitimate-refresh-token"
	validHash := hashToken(validRefreshToken)
	familyID := uuid.New()
	sessionID := uuid.New()

	activeSession := &model.Session{
		ID:               sessionID,
		UserID:           userID,
		FamilyID:         familyID,
		RefreshTokenHash: validHash,
		RefreshExpiresAt: time.Now().Add(24 * time.Hour),
		IsRevoked:        false,
	}
	sessionRepo.sessions[sessionID] = activeSession
	sessionRepo.byRefreshHash[validHash] = activeSession

	resp, appErr := authSvc.RefreshSession(context.Background(), validRefreshToken, service.RequestMeta{})
	if appErr != nil {
		t.Fatalf("expected successful refresh, got: %v", appErr)
	}

	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatal("expected non-empty tokens returned from refresh")
	}

	if len(sessionRepo.rotatedOldSessions) != 1 || sessionRepo.rotatedOldSessions[0] != sessionID {
		t.Fatalf("expected old session %s to be rotated", sessionID)
	}
}

func TestLogoutAll(t *testing.T) {
	userID := uuid.New()
	userRepo := &mockUserRepo{users: make(map[uuid.UUID]*model.User)}
	sessionRepo := newMockSessionRepo()

	authSvc := service.NewAuthService(
		userRepo,
		sessionRepo,
		nil,
		&mockEmailSender{},
		service.AuthConfig{},
		&testLogger{},
	)

	principal := service.AuthPrincipal{UserID: userID.String(), Role: model.RoleUser}
	appErr := authSvc.LogoutAll(context.Background(), principal)
	if appErr != nil {
		t.Fatalf("expected LogoutAll to succeed, got %v", appErr)
	}

	if len(sessionRepo.revokedUserIDs) != 1 || sessionRepo.revokedUserIDs[0] != userID {
		t.Fatalf("expected user %s sessions to be revoked", userID)
	}
}

func TestChangePassword(t *testing.T) {
	userID := uuid.New()
	oldPass := "OldP@ssw0rd123"
	oldHash, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)

	user := &model.User{
		ID:           userID,
		Email:        "user@example.com",
		PasswordHash: string(oldHash),
		Role:         model.RoleUser,
		IsActive:     true,
	}

	userRepo := &mockUserRepo{users: map[uuid.UUID]*model.User{userID: user}}
	sessionRepo := newMockSessionRepo()

	authSvc := service.NewAuthService(
		userRepo,
		sessionRepo,
		nil,
		&mockEmailSender{},
		service.AuthConfig{BcryptCost: bcrypt.DefaultCost},
		&testLogger{},
	)

	principal := service.AuthPrincipal{
		UserID: userID.String(),
		Email:  user.Email,
		Role:   model.RoleUser,
	}

	// Change password
	newPass := "NewSuperP@ssw0rd456"
	appErr := authSvc.ChangePassword(context.Background(), principal, dto.ChangePasswordRequest{
		CurrentPassword: oldPass,
		NewPassword:     newPass,
	})
	if appErr != nil {
		t.Fatalf("expected ChangePassword to succeed, got %v", appErr)
	}

	// Verify new password matches
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(newPass)); err != nil {
		t.Fatalf("expected updated password hash to verify against new password: %v", err)
	}

	// Verify all prior sessions were revoked
	if len(sessionRepo.revokedUserIDs) != 1 || sessionRepo.revokedUserIDs[0] != userID {
		t.Fatalf("expected all sessions revoked on password change")
	}
}
