package service_test

import (
	"testing"
	"time"

	"GoAuth/internal/model"
	"GoAuth/internal/service"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestTokenGenerationAndParsing(t *testing.T) {
	secret := "super-secure-jwt-secret-key-at-least-32-chars-long"
	userID := uuid.New().String()
	email := "user@example.com"
	sessionID := uuid.New().String()
	role := model.RoleUser
	ttl := 15 * time.Minute
	now := time.Now().UTC()

	tokenStr, exp, err := service.GenerateAccessToken(secret, userID, email, sessionID, role, ttl, now)
	if err != nil {
		t.Fatalf("expected no error generating token, got: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}
	if exp.Before(now) {
		t.Fatal("expected expiration to be in the future")
	}

	claims, err := service.ParseAccessToken(secret, tokenStr)
	if err != nil {
		t.Fatalf("expected valid token parsing, got: %v", err)
	}

	if claims.Subject != userID {
		t.Errorf("expected subject %s, got %s", userID, claims.Subject)
	}
	if claims.Email != email {
		t.Errorf("expected email %s, got %s", email, claims.Email)
	}
	if claims.SID != sessionID {
		t.Errorf("expected SID %s, got %s", sessionID, claims.SID)
	}
	if claims.Role != string(role) {
		t.Errorf("expected role %s, got %s", role, claims.Role)
	}
}

func TestTokenExpiration(t *testing.T) {
	secret := "super-secure-jwt-secret-key-at-least-32-chars-long"
	userID := uuid.New().String()
	email := "user@example.com"
	sessionID := uuid.New().String()

	// Generate expired token
	past := time.Now().UTC().Add(-1 * time.Hour)
	tokenStr, _, err := service.GenerateAccessToken(secret, userID, email, sessionID, model.RoleUser, 1*time.Minute, past)
	if err != nil {
		t.Fatalf("expected token generation to succeed, got %v", err)
	}

	_, err = service.ParseAccessToken(secret, tokenStr)
	if err == nil {
		t.Fatal("expected error parsing expired token, got nil")
	}
}

func TestTokenInvalidSignature(t *testing.T) {
	secret1 := "super-secure-jwt-secret-key-at-least-32-chars-long"
	secret2 := "different-secret-key-at-least-32-chars-long-here"

	tokenStr, _, err := service.GenerateAccessToken(secret1, "uid", "test@example.com", "sid", model.RoleUser, 15*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = service.ParseAccessToken(secret2, tokenStr)
	if err == nil {
		t.Fatal("expected signature verification failure with different secret, got nil")
	}
}

func TestAlgorithmConfusionNoneRejected(t *testing.T) {
	secret := "super-secure-jwt-secret-key-at-least-32-chars-long"

	claims := service.AccessTokenClaims{
		Role:  "user",
		Email: "hacker@example.com",
		SID:   "evil-session",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "evil-user",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	}

	// Create token with 'none' signing method
	noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenStr, err := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to create none-signed token: %v", err)
	}

	_, err = service.ParseAccessToken(secret, tokenStr)
	if err == nil {
		t.Fatal("expected rejection of token signed with 'none' algorithm, got nil")
	}
}
