package repository

import (
	"context"
	"database/sql"
)

func PingPostgres(ctx context.Context, db *sql.DB) error {
	return db.PingContext(ctx)
}
