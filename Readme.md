# GoAuth

GoAuth is a REST authentication and session management service built with **Go (`Gin`)**, **PostgreSQL (`pgx/v5`)**, and **Redis**. It implements rotating refresh-token sessions with token-family reuse detection, sliding-window rate limiting, role-based access control, secret-redacted structured logging, and background email workers.

---

## Key Features

- **Session Rotation & Refresh-Token Reuse Detection (`internal/service/auth_service.go`)**:
  - Refresh tokens are grouped by `family_id` and rotated inside a PostgreSQL transaction (`RotateSession`) on every refresh request.
  - If an already-rotated or revoked refresh token is presented again, GoAuth detects the reuse and immediately revokes the entire token family (`RevokeAllByFamilyID`) to force re-authentication across that session chain.
- **Sliding-Window Rate Limiting (`internal/middleware/rate_limiter.go`)**:
  - Protects login (`10 req/min`), signup (`5 req/min`), and OTP verification (`5 req/min`) routes using Redis sorted sets (`ZREMRANGEBYSCORE` + `ZADD` + `ZCARD`).
  - Automatically falls back to an in-memory window limiter if Redis is temporarily unavailable.
- **Structured Logging with Field Redaction (`internal/logger/logger.go`)**:
  - Wraps Go's standard `log/slog` JSON handler with a custom `MaskingHandler` that redacts sensitive keys (`password`, `token`, `refresh_token`, `access_token`, `secret`, `otp`, `authorization`) before logs are written.
- **Background Email Worker Pool (`internal/worker/worker.go`)**:
  - Sends verification and password-reset OTP emails asynchronously via a worker pool (using Mailpit in local development or SMTP in production) with graceful shutdown draining.
- **Role-Based Access Control (`internal/middleware/auth.go`)**:
  - Route middleware enforcing `USER`, `ADMIN`, and `OWNER` roles alongside active-account checks.
- **OpenAPI Spec & CI Pipeline**:
  - Includes an OpenAPI 3.0 specification (`docs/openapi.yaml`), unit and integration tests (`Makefile`), and GitHub Actions workflows running `go test -race`, `golangci-lint`, and `govulncheck`.

---

## Quick Start

### Option 1: Run Everything with Docker Compose

```bash
cp .env.example .env
docker compose up -d --build
```

Services started by `compose.yaml`:
- **GoAuth API**: `http://localhost:8080` (`GET /health`, `GET /ready`)
- **Mailpit Web UI**: `http://localhost:8026` (captures verification and reset OTP emails locally)
- **PostgreSQL**: `localhost:5432`
- **Redis**: `localhost:6380`

### Option 2: Run Locally on Host

```bash
# 1. Start PostgreSQL, Redis, and Mailpit containers
docker compose up -d postgres redis mailpit

# 2. Run database migrations and seed initial admin user
make migrate-up
make seed

# 3. Start the API server
make run
```

---

## Testing & Linting

```bash
# Run unit tests
make test

# Run tests with the Go race detector enabled
make test-race

# Run integration tests
make test-integration

# Run golangci-lint
make lint
```

---

## API Endpoints (`/api/v1`)

Full request and response schemas are documented in [`docs/openapi.yaml`](docs/openapi.yaml).

### Public Authentication Routes
- `POST /api/v1/auth/signup` (or `/api/v1/auth/register`) — Register account and queue email verification OTP
- `POST /api/v1/auth/verify-email` — Verify account email with OTP
- `POST /api/v1/auth/login` — Authenticate and receive a short-lived JWT access token + rotating refresh token
- `POST /api/v1/auth/refresh-session` (or `/api/v1/auth/refresh`) — Rotate refresh token and issue a new token pair
- `POST /api/v1/auth/forgot-password` — Request a password reset OTP
- `POST /api/v1/auth/forgot-password/verify-otp` — Exchange OTP for a short-lived reset token
- `POST /api/v1/auth/password-reset` — Set a new password using the reset token

### Authenticated Session & User Routes (`Bearer <access_token>`)
- `GET /api/v1/users/me` — Get current user profile
- `POST /api/v1/auth/change-password` — Change current user's password
- `GET /api/v1/auth/sessions` — List active login sessions for the current user
- `POST /api/v1/auth/revoke-session` — Revoke a specific session
- `DELETE /api/v1/auth/sessions/:id` — Revoke a session by ID
- `POST /api/v1/auth/logout` — Log out of the current session
- `POST /api/v1/auth/logout-all` — Revoke all active sessions for the current user

### Admin Routes (`ADMIN` Role Required)
- `GET /api/v1/admin/users` — List users with pagination
- `PATCH /api/v1/admin/users/:id/status` — Activate, suspend, or update user status

### Health Probes
- `GET /health` — Liveness probe
- `GET /ready` — Readiness probe (verifies PostgreSQL and Redis connectivity)

---

## Documentation
- [Environment Variables Reference](docs/ENV.md)
- [Database Migrations & Seeding Guide](docs/MIGRATIONS.md)
- [OpenAPI 3.0 Specification](docs/openapi.yaml)
