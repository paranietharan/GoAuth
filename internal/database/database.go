package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

func NewPostgresDB(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	return db, nil
}

func RunMigrations(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			first_name VARCHAR(100),
			last_name VARCHAR(100),
			is_verified BOOLEAN DEFAULT FALSE,
			is_active BOOLEAN DEFAULT TRUE,
			role VARCHAR(50) DEFAULT 'user',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token VARCHAR(255) UNIQUE NOT NULL,
			token_type VARCHAR(50) NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			is_used BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			id SERIAL PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			is_revoked BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token)`,
	}

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("failed to run migration: %w", err)
		}
	}

	return nil
}
