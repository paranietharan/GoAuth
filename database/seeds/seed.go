package seeds

import (
	"database/sql"
	"fmt"
	"log"

	"GoAuth/internal/config"
)

func RunAll(db *sql.DB, cfg *config.Config) error {
	log.Println("Starting database seeding...")

	if err := SeedAdminUser(db, cfg); err != nil {
		return fmt.Errorf("admin user seeding failed: %w", err)
	}

	log.Println("Database seeding completed successfully.")
	return nil
}
