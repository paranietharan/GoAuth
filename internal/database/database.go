package database

import (
	"GoAuth/internal/utils"
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
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
	dropMigrations := []string{
		`DROP TABLE IF EXISTS refresh_tokens CASCADE`,
		`DROP TABLE IF EXISTS tokens CASCADE`,
		`DROP TABLE IF EXISTS role_permissions CASCADE`,
		`DROP TABLE IF EXISTS users CASCADE`,
		`DROP TABLE IF EXISTS permissions CASCADE`,
		`DROP TABLE IF EXISTS roles CASCADE`,
	}

	log.Println("Dropping existing tables...")
	for i, migration := range dropMigrations {
		log.Printf("Dropping table %d/%d", i+1, len(dropMigrations))
		if _, err := db.Exec(migration); err != nil {
			log.Printf("Warning: Failed to drop: %v", err)
		}
	}
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS roles (
			id SERIAL PRIMARY KEY,
			name VARCHAR(50) UNIQUE NOT NULL,
			description VARCHAR(255),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)`,
		`CREATE TABLE IF NOT EXISTS permissions (
			id SERIAL PRIMARY KEY,
			name VARCHAR(100) UNIQUE NOT NULL,
			description VARCHAR(255),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name)`,
		`CREATE TABLE IF NOT EXISTS role_permissions (
			id SERIAL PRIMARY KEY,
			role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
			permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(role_id, permission_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id)`,
		`CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id)`,
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(255) PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			first_name VARCHAR(100),
			last_name VARCHAR(100),
			is_verified BOOLEAN DEFAULT FALSE,
			is_active BOOLEAN DEFAULT TRUE,
			role_id INTEGER REFERENCES roles(id) ON DELETE SET NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id SERIAL PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
			user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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

// Seed sample db users
func SeedDatabase(db *sql.DB) error {
	log.Println("Starting database seeding...")

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM roles").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check existing roles: %w", err)
	}

	if count > 0 {
		log.Println("Database already seeded, skipping...")
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	roles := []struct {
		name        string
		description string
	}{
		{"admin", "Administrator with full access"},
		{"moderator", "Moderator with limited admin access"},
		{"user", "Regular user"},
		{"guest", "Guest user with read-only access"},
	}

	roleIDs := make(map[string]int)
	for _, role := range roles {
		var id int
		err := tx.QueryRow(
			"INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING id",
			role.name,
			role.description,
		).Scan(&id)
		if err != nil {
			return fmt.Errorf("failed to seed role %s: %w", role.name, err)
		}
		roleIDs[role.name] = id
		log.Printf("Seeded role: %s (ID: %d)", role.name, id)
	}

	permissions := []struct {
		name        string
		description string
	}{
		{"users.create", "Create new users"},
		{"users.read", "Read user information"},
		{"users.update", "Update user information"},
		{"users.delete", "Delete users"},
		{"roles.manage", "Manage roles and permissions"},
		{"posts.create", "Create posts"},
		{"posts.read", "Read posts"},
		{"posts.update", "Update posts"},
		{"posts.delete", "Delete posts"},
		{"settings.manage", "Manage system settings"},
	}

	permIDs := make(map[string]int)
	for _, perm := range permissions {
		var id int
		err := tx.QueryRow(
			"INSERT INTO permissions (name, description) VALUES ($1, $2) RETURNING id",
			perm.name,
			perm.description,
		).Scan(&id)
		if err != nil {
			return fmt.Errorf("failed to seed permission %s: %w", perm.name, err)
		}
		permIDs[perm.name] = id
		log.Printf("Seeded permission: %s (ID: %d)", perm.name, id)
	}

	rolePermissions := map[string][]string{
		"admin": {
			"users.create", "users.read", "users.update", "users.delete",
			"roles.manage", "posts.create", "posts.read", "posts.update", "posts.delete",
			"settings.manage",
		},
		"moderator": {
			"users.read", "posts.read", "posts.update", "posts.delete",
		},
		"user": {
			"users.read", "posts.create", "posts.read", "posts.update",
		},
		"guest": {
			"posts.read",
		},
	}

	for roleName, permNames := range rolePermissions {
		roleID := roleIDs[roleName]
		for _, permName := range permNames {
			permID := permIDs[permName]
			_, err := tx.Exec(
				"INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
				roleID,
				permID,
			)
			if err != nil {
				return fmt.Errorf("failed to assign permission %s to role %s: %w", permName, roleName, err)
			}
		}
		log.Printf("Assigned %d permissions to role: %s", len(permNames), roleName)
	}

	users := []struct {
		email     string
		password  string
		firstName string
		lastName  string
		roleKey   string
	}{
		{
			email:     "admin@example.com",
			password:  "Admin@123456",
			firstName: "Admin",
			lastName:  "User",
			roleKey:   "admin",
		},
		{
			email:     "moderator@example.com",
			password:  "Moderator@123456",
			firstName: "Moderator",
			lastName:  "User",
			roleKey:   "moderator",
		},
		{
			email:     "john@example.com",
			password:  "John@123456",
			firstName: "John",
			lastName:  "Doe",
			roleKey:   "user",
		},
		{
			email:     "jane@example.com",
			password:  "Jane@123456",
			firstName: "Jane",
			lastName:  "Smith",
			roleKey:   "user",
		},
		{
			email:     "guest@example.com",
			password:  "Guest@123456",
			firstName: "Guest",
			lastName:  "User",
			roleKey:   "guest",
		},
	}

	for _, user := range users {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password for %s: %w", user.email, err)
		}

		roleID := roleIDs[user.roleKey]
		userUUID := utils.GenerateUUID()

		_, err = tx.Exec(
			"INSERT INTO users (id, email, password_hash, first_name, last_name, role_id, is_verified, is_active) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
			userUUID, // Use UUID as ID
			user.email,
			string(hashedPassword),
			user.firstName,
			user.lastName,
			roleID,
			true, // is_verified
			true, // is_active
		)
		if err != nil {
			return fmt.Errorf("failed to seed user %s: %w", user.email, err)
		}
		log.Printf("Seeded user: %s (Role: %s, UUID: %s)", user.email, user.roleKey, userUUID)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Println("Database seeding completed successfully!")
	return nil
}
