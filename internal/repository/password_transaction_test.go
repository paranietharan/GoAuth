package repository

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"os"
	"testing"
)

func TestPasswordRollbackOnSessionUpdateFailure(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	_, err = db.Exec(`CREATE TEMP TABLE users (id uuid PRIMARY KEY,password_hash text,updated_at timestamptz);
        CREATE TEMP TABLE sessions(user_id uuid,is_revoked boolean CHECK (NOT is_revoked),updated_at timestamptz)`)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err = db.Exec("INSERT INTO users(id,password_hash) VALUES($1,'old')", id); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO sessions(user_id,is_revoked) VALUES($1,false)", id); err != nil {
		t.Fatal(err)
	}
	if err := NewPostgresUserRepository(db).UpdatePasswordAndRevokeSessions(ctx, id, "new"); err == nil {
		t.Fatal("expected session constraint to reject update")
	}
	var hash string
	if err = db.QueryRow("SELECT password_hash FROM users WHERE id=$1", id).Scan(&hash); err != nil || hash != "old" {
		t.Fatalf("password changed despite rollback: %q %v", hash, err)
	}
}
