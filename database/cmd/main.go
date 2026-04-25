package main

import (
	"flag"
	"log"

	"GoAuth/database/runner"
	"GoAuth/internal/config"
	"GoAuth/internal/database"

	_ "github.com/lib/pq"
)

func main() {
	migrateCmd := flag.String("migrate", "", "Migration command: up, down, or drop")
	seedCmd := flag.Bool("seed", false, "Run database seeds")
	flag.Parse()

	cfg := config.Load()

	db, err := database.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if *migrateCmd != "" {
		switch *migrateCmd {
		case "up":
			if err := runner.MigrateUp(db, "database/migrations"); err != nil {
				log.Fatalf("Migration up failed: %v", err)
			}
		case "drop":
			if err := runner.DropAll(db); err != nil {
				log.Fatalf("Drop all failed: %v", err)
			}
		default:
			log.Fatalf("Unknown migration command: %s. Use 'up' or 'drop'.", *migrateCmd)
		}
	}

	if *seedCmd {
		if err := runner.RunSeeds(db, cfg); err != nil {
			log.Fatalf("Seeding failed: %v", err)
		}
	}

	if *migrateCmd == "" && !*seedCmd {
		log.Println("No command provided. Use -migrate up|drop or -seed")
	}
}
