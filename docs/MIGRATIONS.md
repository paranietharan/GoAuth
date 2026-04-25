# Database Migrations & Seeding Documentation

## 1. Directory Structure

- `database/migrations/`: SQL migration files (`.up.sql`).
- `database/seeds/`: Go seed files.
- `database/runner/`: Migration and seed execution logic.
- `database/cmd/`: CLI tool entry point.

---

## 2. Running Migrations & Seeds

### Manual Execution (CLI)
Use the database tool to run migrations or seeds manually:

```bash
# Apply all pending migrations
go run database/cmd/main.go -migrate up

# Drop all tables and types (WARNING: Destructive)
go run database/cmd/main.go -migrate drop

# Run database seeds
go run database/cmd/main.go -seed

# Run both migrations and seeds
go run database/cmd/main.go -migrate up -seed
```

---

## 3. Configuration

Set environment variables to customize the behavior:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgres://...` | Connection string for PostgreSQL. |
| `SEED_OWNER_EMAIL` | `admin@goauth.com` | Email for the default OWNER user. |
| `SEED_OWNER_PASSWORD` | `Admin@123` | Password for the default OWNER user. |

---
