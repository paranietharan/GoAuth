package config

import (
	"os"
	"strings"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	// Helper to clear environment variables for test isolation
	clearEnv := func() {
		os.Unsetenv("PORT")
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("REDIS_ADDR")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("IS_LOCAL_DEV_WITHOUT_SMTP")
		os.Unsetenv("SMTP_HOST")
		os.Unsetenv("SMTP_PORT")
		os.Unsetenv("SMTP_FROM")
		os.Unsetenv("BCRYPT_COST")
		os.Unsetenv("ACCESS_TOKEN_TTL_MINUTES")
	}

	t.Run("missing required variables returns consolidated error", func(t *testing.T) {
		clearEnv()

		cfg, err := Load()
		if err == nil {
			t.Fatal("expected error when required config is missing, got nil")
		}
		if cfg != nil {
			t.Fatal("expected nil config on error")
		}

		errStr := err.Error()
		if !strings.Contains(errStr, "DATABASE_URL is required") {
			t.Errorf("expected DATABASE_URL error, got: %s", errStr)
		}
		if !strings.Contains(errStr, "REDIS_ADDR is required") {
			t.Errorf("expected REDIS_ADDR error, got: %s", errStr)
		}
		if !strings.Contains(errStr, "JWT_SECRET is required") {
			t.Errorf("expected JWT_SECRET error, got: %s", errStr)
		}
	})

	t.Run("short JWT_SECRET is rejected", func(t *testing.T) {
		clearEnv()
		os.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
		os.Setenv("REDIS_ADDR", "localhost:6379")
		os.Setenv("JWT_SECRET", "too-short-secret")
		os.Setenv("IS_LOCAL_DEV_WITHOUT_SMTP", "true")

		_, err := Load()
		if err == nil {
			t.Fatal("expected error for short JWT_SECRET, got nil")
		}
		if !strings.Contains(err.Error(), "JWT_SECRET must be at least 32 characters") {
			t.Errorf("expected JWT_SECRET length error, got: %v", err)
		}
	})

	t.Run("invalid integer value returns error", func(t *testing.T) {
		clearEnv()
		os.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
		os.Setenv("REDIS_ADDR", "localhost:6379")
		os.Setenv("JWT_SECRET", "12345678901234567890123456789012")
		os.Setenv("IS_LOCAL_DEV_WITHOUT_SMTP", "true")
		os.Setenv("BCRYPT_COST", "not-a-number")

		_, err := Load()
		if err == nil {
			t.Fatal("expected error for invalid BCRYPT_COST integer, got nil")
		}
		if !strings.Contains(err.Error(), "invalid integer value for BCRYPT_COST") {
			t.Errorf("expected BCRYPT_COST parse error, got: %v", err)
		}
	})

	t.Run("valid configuration succeeds", func(t *testing.T) {
		clearEnv()
		os.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
		os.Setenv("REDIS_ADDR", "localhost:6379")
		os.Setenv("JWT_SECRET", "12345678901234567890123456789012")
		os.Setenv("IS_LOCAL_DEV_WITHOUT_SMTP", "false")
		os.Setenv("SMTP_HOST", "mailpit")
		os.Setenv("SMTP_PORT", "1025")
		os.Setenv("SMTP_FROM", "test@goauth.local")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("unexpected error for valid config: %v", err)
		}
		if cfg.Port != "8080" {
			t.Errorf("expected default PORT 8080, got %s", cfg.Port)
		}
		if cfg.BcryptCost != 12 {
			t.Errorf("expected default BCRYPT_COST 12, got %d", cfg.BcryptCost)
		}
	})
}
