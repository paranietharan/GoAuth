package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Port        string
	DatabaseURL string
	RedisAddr   string
	RedisPass   string
	RedisDB     int
	JWTSecret   string

	SeedAdminEmail    string
	SeedAdminPassword string

	BcryptCost            int
	AccessTokenTTLMinutes int
	RefreshTokenTTLDays   int
	EmailVerificationTTL  time.Duration
	ForgotPasswordOTPTTL  time.Duration
	ResetTempTokenTTL     time.Duration

	IsLocalDevWithoutSMTP bool
	SMTPHost              string
	SMTPPort              string
	SMTPUser              string
	SMTPPassword          string
	SMTPFrom              string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	var errs []string

	bcryptCost, err := getEnvInt("BCRYPT_COST", 12)
	if err != nil {
		errs = append(errs, err.Error())
	}

	accessTTL, err := getEnvInt("ACCESS_TOKEN_TTL_MINUTES", 15)
	if err != nil {
		errs = append(errs, err.Error())
	}

	refreshTTL, err := getEnvInt("REFRESH_TOKEN_TTL_DAYS", 30)
	if err != nil {
		errs = append(errs, err.Error())
	}

	emailVerifyTTL, err := getEnvInt("EMAIL_VERIFICATION_TTL_MINUTES", 10)
	if err != nil {
		errs = append(errs, err.Error())
	}

	forgotOTPTTL, err := getEnvInt("FORGOT_PASSWORD_OTP_TTL_MINUTES", 10)
	if err != nil {
		errs = append(errs, err.Error())
	}

	resetTempTTL, err := getEnvInt("RESET_TEMP_TOKEN_TTL_MINUTES", 15)
	if err != nil {
		errs = append(errs, err.Error())
	}

	redisDB, err := getEnvInt("REDIS_DB", 0)
	if err != nil {
		errs = append(errs, err.Error())
	}

	isLocalDevWithoutSMTP, err := getEnvBool("IS_LOCAL_DEV_WITHOUT_SMTP", false)
	if err != nil {
		errs = append(errs, err.Error())
	}

	cfg := &Config{
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: strings.TrimSpace(os.Getenv("DATABASE_URL")),
		RedisAddr:   strings.TrimSpace(os.Getenv("REDIS_ADDR")),
		RedisPass:   os.Getenv("REDIS_PASSWORD"),
		RedisDB:     redisDB,
		JWTSecret:   strings.TrimSpace(os.Getenv("JWT_SECRET")),

		SeedAdminEmail:    getEnv("SEED_ADMIN_EMAIL", "admin@goauth.com"),
		SeedAdminPassword: getEnv("SEED_ADMIN_PASSWORD", "Admin@123"),

		BcryptCost:            bcryptCost,
		AccessTokenTTLMinutes: accessTTL,
		RefreshTokenTTLDays:   refreshTTL,
		EmailVerificationTTL:  time.Duration(emailVerifyTTL) * time.Minute,
		ForgotPasswordOTPTTL:  time.Duration(forgotOTPTTL) * time.Minute,
		ResetTempTokenTTL:     time.Duration(resetTempTTL) * time.Minute,

		IsLocalDevWithoutSMTP: isLocalDevWithoutSMTP,
		SMTPHost:              strings.TrimSpace(os.Getenv("SMTP_HOST")),
		SMTPPort:              strings.TrimSpace(os.Getenv("SMTP_PORT")),
		SMTPUser:              os.Getenv("SMTP_USER"),
		SMTPPassword:          os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:              strings.TrimSpace(os.Getenv("SMTP_FROM")),
	}

	if valErrs := cfg.validate(); len(valErrs) > 0 {
		errs = append(errs, valErrs...)
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("configuration errors:\n - %s", strings.Join(errs, "\n - "))
	}

	return cfg, nil
}

func (c *Config) validate() []string {
	var errs []string

	if c.DatabaseURL == "" {
		errs = append(errs, "DATABASE_URL is required and cannot be empty")
	}

	if c.RedisAddr == "" {
		errs = append(errs, "REDIS_ADDR is required and cannot be empty")
	}

	if c.JWTSecret == "" {
		errs = append(errs, "JWT_SECRET is required and cannot be empty")
	} else if len(c.JWTSecret) < 32 {
		errs = append(errs, "JWT_SECRET must be at least 32 characters long for secure signing")
	}

	if !c.IsLocalDevWithoutSMTP {
		if c.SMTPHost == "" {
			errs = append(errs, "SMTP_HOST is required when IS_LOCAL_DEV_WITHOUT_SMTP is false")
		}
		if c.SMTPPort == "" {
			errs = append(errs, "SMTP_PORT is required when IS_LOCAL_DEV_WITHOUT_SMTP is false")
		}
		if c.SMTPFrom == "" {
			errs = append(errs, "SMTP_FROM is required when IS_LOCAL_DEV_WITHOUT_SMTP is false")
		}
	}

	if c.BcryptCost < bcrypt.MinCost || c.BcryptCost > bcrypt.MaxCost {
		errs = append(errs, fmt.Sprintf("BCRYPT_COST must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost))
	}

	if c.AccessTokenTTLMinutes <= 0 {
		errs = append(errs, "ACCESS_TOKEN_TTL_MINUTES must be greater than 0")
	}

	if c.RefreshTokenTTLDays <= 0 {
		errs = append(errs, "REFRESH_TOKEN_TTL_DAYS must be greater than 0")
	}

	if c.EmailVerificationTTL <= 0 {
		errs = append(errs, "EMAIL_VERIFICATION_TTL_MINUTES must be greater than 0")
	}

	if c.ForgotPasswordOTPTTL <= 0 {
		errs = append(errs, "FORGOT_PASSWORD_OTP_TTL_MINUTES must be greater than 0")
	}

	if c.ResetTempTokenTTL <= 0 {
		errs = append(errs, "RESET_TEMP_TOKEN_TTL_MINUTES must be greater than 0")
	}

	if c.RedisDB < 0 {
		errs = append(errs, "REDIS_DB cannot be negative")
	}

	return errs
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) (bool, error) {
	value, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(value) == "" {
		return defaultValue, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, fmt.Errorf("invalid boolean value for %s: %q", key, value)
	}
	return b, nil
}

func getEnvInt(key string, defaultValue int) (int, error) {
	value, exists := os.LookupEnv(key)
	if !exists || strings.TrimSpace(value) == "" {
		return defaultValue, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("invalid integer value for %s: %q", key, value)
	}
	return n, nil
}
