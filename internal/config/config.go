package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port        string
	DatabaseURL string
	JWTSecret   string

	// SMTP
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string

	RUN_Drop_Migrations bool
	RUN_Migrations      bool
	SEED_DB             bool
}

func Load() *Config {
	return &Config{
		Port:         getEnv("PORT", "8080"),
		DatabaseURL:  getEnv("DATABASE_URL", "postgres://postgres:root@localhost:5432/GoAuth?sslmode=disable"),
		JWTSecret:    getEnv("JWT_SECRET", "your-secret-key-change-this"),
		SMTPHost:     getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:     getEnv("SMTP_PORT", "587"),
		SMTPUser:     getEnv("SMTP_USER", "your-email@gmail.com"),
		SMTPPassword: getEnv("SMTP_PASSWORD", "your-app-password"),
		SMTPFrom:     getEnv("SMTP_FROM", "noreply@GoAuth.com"),

		RUN_Migrations:      getEnvBool("RUN_MIGRATIONS", true),
		RUN_Drop_Migrations: getEnvBool("RUN_DROP_MIGRATIONS", true),
		SEED_DB:             getEnvBool("SEED_DB", true),
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
