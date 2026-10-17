package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"GoAuth/internal/database"
	"GoAuth/internal/dto"
	"GoAuth/internal/handler"
	"GoAuth/internal/logger"
	"GoAuth/internal/middleware"
	"GoAuth/internal/notification/email"
	"GoAuth/internal/repository"
	"GoAuth/internal/router"
	"GoAuth/internal/service"
	"GoAuth/internal/worker"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func setupTestApp(t *testing.T) (*gin.Engine, *repository.RedisOTPRepository, func()) {
	gin.SetMode(gin.TestMode)

	// Integration database connection
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:root@localhost:5432/go_auth?sslmode=disable"
	}
	db, err := database.NewPostgresDB(dbURL)
	if err != nil {
		t.Skipf("skipping integration test: database unreachable (%v)", err)
		return nil, nil, nil
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6380"
	}
	redisClient := database.NewRedisClient(redisAddr, "", 0)
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		_ = db.Close()
		t.Skipf("skipping integration test: redis unreachable (%v)", err)
		return nil, nil, nil
	}

	appLogger := logger.New(false)
	jobQueue := worker.NewJobQueue(50)
	mockProvider := &email.MockProvider{}
	renderer, _ := email.NewRenderer("../../internal/notification/email/templates")
	emailSender := email.NewService(mockProvider, renderer, jobQueue)

	userRepo := repository.NewPostgresUserRepository(db)
	sessionRepo := repository.NewPostgresSessionRepository(db)
	otpRepo := repository.NewRedisOTPRepository(redisClient)

	jwtSecret := "integration-test-secure-jwt-secret-at-least-32-chars"
	authSvc := service.NewAuthService(
		userRepo,
		sessionRepo,
		otpRepo,
		emailSender,
		service.AuthConfig{
			JWTSecret:            jwtSecret,
			BcryptCost:           10,
			AccessTokenTTL:       15 * time.Minute,
			RefreshTokenTTL:      7 * 24 * time.Hour,
			EmailVerificationTTL: 10 * time.Minute,
			ForgotPasswordOTPTTL: 10 * time.Minute,
			ResetTempTokenTTL:    15 * time.Minute,
		},
		appLogger,
	)

	authMw := middleware.NewAuthMiddleware(jwtSecret, sessionRepo, userRepo)
	authH := handler.NewAuthHandler(authSvc)
	healthH := handler.NewHealthHandler(db, redisClient)
	rateLimiter := middleware.NewRateLimiter(redisClient)

	engine := router.New(router.Config{
		AuthHandler:    authH,
		HealthHandler:  healthH,
		AuthMiddleware: authMw,
		RateLimiter:    rateLimiter,
		CORSConfig:     middleware.DefaultCORSConfig([]string{"*"}),
		Logger:         appLogger,
	})

	teardown := func() {
		_ = db.Close()
		_ = redisClient.Close()
	}

	return engine, otpRepo, teardown
}

func performRequest(engine *gin.Engine, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var bodyReader *bytes.Reader
	if body != nil {
		jsonBytes, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(jsonBytes)
	} else {
		bodyReader = bytes.NewReader([]byte{})
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func TestCompleteAuthLifecycle(t *testing.T) {
	engine, otpRepo, teardown := setupTestApp(t)
	if engine == nil {
		return
	}
	defer teardown()

	email := fmt.Sprintf("testuser_%s@example.com", uuid.New().String()[:8])
	password := "StrongP@ssw0rd123!"

	// 1. Signup
	w := performRequest(engine, http.MethodPost, "/api/v1/auth/signup", dto.SignupRequest{
		Email:    email,
		Password: password,
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("signup failed with status %d: %s", w.Code, w.Body.String())
	}

	// 2. Fetch OTP from Redis and verify email
	otp, found, err := otpRepo.GetEmailVerificationOTP(context.Background(), email)
	if err != nil || !found {
		t.Fatalf("failed to retrieve signup OTP from redis: %v", err)
	}

	w = performRequest(engine, http.MethodPost, "/api/v1/auth/verify-email", dto.VerifyEmailRequest{
		Email: email,
		OTP:   otp,
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("verify email failed with status %d: %s", w.Code, w.Body.String())
	}

	// 3. Login
	w = performRequest(engine, http.MethodPost, "/api/v1/auth/login", dto.LoginRequest{
		Email:    email,
		Password: password,
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed with status %d: %s", w.Code, w.Body.String())
	}

	var loginResp dto.AuthTokensResponse
	if err := json.Unmarshal(w.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("failed to parse login response: %v", err)
	}
	if loginResp.AccessToken == "" || loginResp.RefreshToken == "" {
		t.Fatal("expected access and refresh tokens in login response")
	}

	// 4. Access protected profile /api/v1/users/me
	authHeader := map[string]string{"Authorization": "Bearer " + loginResp.AccessToken}
	w = performRequest(engine, http.MethodGet, "/api/v1/users/me", nil, authHeader)
	if w.Code != http.StatusOK {
		t.Fatalf("get me failed with status %d: %s", w.Code, w.Body.String())
	}

	// 5. Refresh token rotation
	w = performRequest(engine, http.MethodPost, "/api/v1/auth/refresh", dto.RefreshSessionRequest{
		RefreshToken: loginResp.RefreshToken,
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh failed with status %d: %s", w.Code, w.Body.String())
	}

	var refreshResp dto.AuthTokensResponse
	if err := json.Unmarshal(w.Body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("failed to parse refresh response: %v", err)
	}
	if refreshResp.AccessToken == "" || refreshResp.RefreshToken == "" {
		t.Fatal("expected new access and refresh tokens")
	}

	// 6. Token Reuse Detection Test:
	// Attacker tries to reuse old rotated refresh token
	w = performRequest(engine, http.MethodPost, "/api/v1/auth/refresh", dto.RefreshSessionRequest{
		RefreshToken: loginResp.RefreshToken,
	}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 on reuse of rotated token, got %d: %s", w.Code, w.Body.String())
	}

	// Token family should now be revoked! The newly issued refresh token must now ALSO fail
	w = performRequest(engine, http.MethodPost, "/api/v1/auth/refresh", dto.RefreshSessionRequest{
		RefreshToken: refreshResp.RefreshToken,
	}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected descendant token to be revoked after reuse detection, got status %d", w.Code)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	engine, _, teardown := setupTestApp(t)
	if engine == nil {
		return
	}
	defer teardown()

	w := performRequest(engine, http.MethodGet, "/health", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected /health to return 200, got %d", w.Code)
	}

	w = performRequest(engine, http.MethodGet, "/ready", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected /ready to return 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestConcurrentRefreshSafety(t *testing.T) {
	engine, otpRepo, teardown := setupTestApp(t)
	if engine == nil {
		return
	}
	defer teardown()

	email := fmt.Sprintf("concurrent_%s@example.com", uuid.New().String()[:8])
	password := "StrongP@ssw0rd123!"

	// Signup & Verify
	_ = performRequest(engine, http.MethodPost, "/api/v1/auth/signup", dto.SignupRequest{
		Email:    email,
		Password: password,
	}, nil)
	otp, _, _ := otpRepo.GetEmailVerificationOTP(context.Background(), email)
	_ = performRequest(engine, http.MethodPost, "/api/v1/auth/verify-email", dto.VerifyEmailRequest{
		Email: email,
		OTP:   otp,
	}, nil)

	// Login
	w := performRequest(engine, http.MethodPost, "/api/v1/auth/login", dto.LoginRequest{
		Email:    email,
		Password: password,
	}, nil)
	var loginResp dto.AuthTokensResponse
	_ = json.Unmarshal(w.Body.Bytes(), &loginResp)

	// Spawn parallel refresh requests with the SAME token
	type res struct {
		status int
	}
	ch := make(chan res, 2)
	for i := 0; i < 2; i++ {
		go func() {
			rw := performRequest(engine, http.MethodPost, "/api/v1/auth/refresh", dto.RefreshSessionRequest{
				RefreshToken: loginResp.RefreshToken,
			}, nil)
			ch <- res{status: rw.Code}
		}()
	}

	var statuses []int
	for i := 0; i < 2; i++ {
		r := <-ch
		statuses = append(statuses, r.status)
	}

	// At most 1 request should succeed (200), the other must fail (401)
	successCount := 0
	for _, s := range statuses {
		if s == http.StatusOK {
			successCount++
		}
	}
	if successCount > 1 {
		t.Fatalf("expected at most 1 concurrent refresh to succeed, but got %d", successCount)
	}
}

func TestRBACAndUserDeactivation(t *testing.T) {
	engine, otpRepo, teardown := setupTestApp(t)
	if engine == nil {
		return
	}
	defer teardown()

	email := fmt.Sprintf("regular_%s@example.com", uuid.New().String()[:8])
	password := "StrongP@ssw0rd123!"

	// Signup & Verify regular user
	_ = performRequest(engine, http.MethodPost, "/api/v1/auth/signup", dto.SignupRequest{
		Email:    email,
		Password: password,
	}, nil)
	otp, _, _ := otpRepo.GetEmailVerificationOTP(context.Background(), email)
	_ = performRequest(engine, http.MethodPost, "/api/v1/auth/verify-email", dto.VerifyEmailRequest{
		Email: email,
		OTP:   otp,
	}, nil)

	// Login regular user
	w := performRequest(engine, http.MethodPost, "/api/v1/auth/login", dto.LoginRequest{
		Email:    email,
		Password: password,
	}, nil)
	var userTokens dto.AuthTokensResponse
	_ = json.Unmarshal(w.Body.Bytes(), &userTokens)

	// Regular user calling admin-only endpoint -> 403 Forbidden
	userAuthHeader := map[string]string{"Authorization": "Bearer " + userTokens.AccessToken}
	w = performRequest(engine, http.MethodGet, "/api/v1/admin/users", nil, userAuthHeader)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for regular user accessing /admin/users, got %d", w.Code)
	}
}

