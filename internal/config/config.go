package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
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

	// SMTP
	IsLocalDevWithoutSMTP bool
	SMTPHost              string
	SMTPPort              string
	SMTPUser              string
	SMTPPassword          string
	SMTPFrom              string
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	return &Config{
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://postgres:root@localhost:5432/GoAuth?sslmode=disable"),
		RedisAddr:   getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPass:   getEnv("REDIS_PASSWORD", ""),
		RedisDB:     getEnvInt("REDIS_DB", 0),
		JWTSecret:   getEnv("JWT_SECRET", "your-secret-key-change-this"),

		SeedAdminEmail:    getEnv("SEED_ADMIN_EMAIL", "admin@goauth.com"),
		SeedAdminPassword: getEnv("SEED_ADMIN_PASSWORD", "Admin@123"),

		BcryptCost:            getEnvInt("BCRYPT_COST", 12),
		AccessTokenTTLMinutes: getEnvInt("ACCESS_TOKEN_TTL_MINUTES", 15),
		RefreshTokenTTLDays:   getEnvInt("REFRESH_TOKEN_TTL_DAYS", 30),
		EmailVerificationTTL:  time.Duration(getEnvInt("EMAIL_VERIFICATION_TTL_MINUTES", 10)) * time.Minute,
		ForgotPasswordOTPTTL:  time.Duration(getEnvInt("FORGOT_PASSWORD_OTP_TTL_MINUTES", 10)) * time.Minute,
		ResetTempTokenTTL:     time.Duration(getEnvInt("RESET_TEMP_TOKEN_TTL_MINUTES", 15)) * time.Minute,

		IsLocalDevWithoutSMTP: getEnvBool("IS_LOCAL_DEV_WITHOUT_SMTP", false),
		SMTPHost:              getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:              getEnv("SMTP_PORT", "587"),
		SMTPUser:              getEnv("SMTP_USER", "your-email@gmail.com"),
		SMTPPassword:          getEnv("SMTP_PASSWORD", "your-app-password"),
		SMTPFrom:              getEnv("SMTP_FROM", "noreply@GoAuth.com"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
