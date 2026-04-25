package runner

import (
	"database/sql"
	"fmt"

	"GoAuth/database/seeds"
	"GoAuth/internal/config"
)

func RunSeeds(db *sql.DB, cfg *config.Config) error {
	if err := seeds.RunAll(db, cfg); err != nil {
		return fmt.Errorf("seeding failed: %w", err)
	}
	return nil
}
