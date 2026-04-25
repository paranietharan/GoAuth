package seeds

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"GoAuth/internal/config"
	"GoAuth/internal/model"

	"golang.org/x/crypto/bcrypt"
)

func SeedAdminUser(db *sql.DB, cfg *config.Config) error {
	ctx := context.Background()

	// Check if admin already exists
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
	err := db.QueryRowContext(ctx, query, cfg.SeedAdminEmail).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if admin exists: %w", err)
	}

	if exists {
		log.Printf("Seed: Admin user %s already exists. Skipping...", cfg.SeedAdminEmail)
		return nil
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(cfg.SeedAdminPassword), cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	// Create admin user (using ADMIN role for bootstrap)
	insertQuery := `
		INSERT INTO users (email, password_hash, role, is_active, is_email_verified, email_verified_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`
	_, err = db.ExecContext(ctx, insertQuery, cfg.SeedAdminEmail, string(passwordHash), model.RoleAdmin, true, true)
	if err != nil {
		return fmt.Errorf("failed to insert admin user: %w", err)
	}

	log.Printf("Seed: Successfully created admin user: %s", cfg.SeedAdminEmail)
	return nil
}
