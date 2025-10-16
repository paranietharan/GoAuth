package config

import (
	"os"
)

type Config struct {
	Port         string
	DatabaseURL  string
	JWTSecret    string
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	AppURL       string
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
		AppURL:       getEnv("APP_URL", "http://localhost:8080"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
