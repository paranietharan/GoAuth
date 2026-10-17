# GoAuth Template — Implementation Roadmap & TODO

This document tracks all missing features, security enhancements, testing requirements, and developer experience improvements needed to transform **GoAuth** into a production-grade, reusable authentication foundation for monolithic Go APIs, adhering to [`go_authentication_template_requirements.md`](./go_authentication_template_requirements.md).

---

## 📊 Requirements Gap Analysis Summary

| Category | Requirement Area | Status | Priority |
| :--- | :--- | :--- | :--- |
| **Auth & Tokens** | Refresh-token rotation & reuse detection | ✅ Implemented (Family tracking & descendant revocation) | **P0 (Critical)** |
| **Auth & Tokens** | Concurrent refresh request safety | ✅ Implemented (Atomic rotation check in DB transaction) | **P0 (Critical)** |
| **Auth & Tokens** | Missing endpoints (`logout-all`, `change-password`, `users/me`) | ✅ Implemented and mounted | **P0 (Critical)** |
| **Auth & Tokens** | JWT Algorithm Hardening | ✅ Implemented (HS256 whitelist enforced) | **P1 (High)** |
| **Security** | Rate limiting (Login, Signup, Forgot-Password) | ✅ Implemented (Redis sliding window with memory fallback) | **P0 (Critical)** |
| **Security** | CORS Configuration Middleware | ✅ Implemented (Configurable origins, methods, headers) | **P1 (High)** |
| **Security** | Security Audit Logging (failures, reuse, revocations) | ✅ Implemented (`SECURITY_AUDIT` logs with secret masking) | **P1 (High)** |
| **Quality** | Unit & Integration Tests | ✅ Implemented (100% passing test suite with `-race`) | **P0 (Critical)** |
| **Quality** | CI/CD Pipeline (GitHub Actions) | ✅ Implemented (`.github/workflows/ci.yml`) | **P1 (High)** |
| **Operations** | Structured logging (`slog`) with secret masking | ✅ Implemented (`MaskingHandler` redacting sensitive keys) | **P1 (High)** |
| **Operations** | Health & Readiness endpoints (`/health`, `/ready`) | ✅ Implemented (Liveness + Postgres/Redis ping) | **P1 (High)** |
| **Operations** | Config validation at startup | ✅ Implemented (Fail-fast consolidated validation) | **P1 (High)** |
| **DevOps** | Dockerfile & Docker Compose | ✅ Implemented (Multi-stage + compose without fallback defaults) | **P1 (High)** |
| **DevOps** | Database down migrations (`.down.sql`) | ✅ Implemented (Versioned up & down migrations) | **P2 (Medium)** |
| **DevOps** | Makefile for developer workflows | ✅ Implemented (Build, test, run, migrations, compose) | **P2 (Medium)** |
| **Docs & DX** | Reusable integration guide in README | ✅ Implemented (Comprehensive guide & architecture diagrams) | **P0 (Critical)** |
| **Docs & DX** | OpenAPI / Swagger specification | ✅ Implemented (`docs/openapi.yaml`) | **P1 (High)** |
| **Docs & DX** | Practical `curl` examples & monolithic integration example | ✅ Implemented (`examples/monolith/main.go` & curl examples) | **P1 (High)** |

---

## 🚀 Step-by-Step Implementation Roadmap

### Phase 1: Core Token Lifecycle, Reuse Detection & Bug Fixes (P0)

- [x] **1.1 Implement Token Family & Refresh Token Reuse Detection**
  - [x] Add `family_id UUID` column to `sessions` table (create migration `000003_add_session_family.up.sql` and `.down.sql`).
  - [x] Update `model.Session` to include `FamilyID uuid.UUID`.
  - [x] On login: Assign `family_id = session.id`.
  - [x] On refresh: Carry forward `newSession.family_id = oldSession.family_id`.
  - [x] In `authService.RefreshSession`:
    - Detect if presented refresh token belongs to an **already revoked** session.
    - If reuse is detected: Immediately revoke **all active sessions** within that `family_id` (or for that user), trigger a critical security audit event, and return `401 Unauthorized`.
    - Revoke descendant sessions to prevent token hijacking.
  - [x] Store `family_id` in repository queries and session creation.

- [x] **1.2 Handle Concurrent Refresh Requests Safely**
  - [x] Implement atomic rotation check using database transaction / conditional update (`UPDATE sessions SET is_revoked = TRUE WHERE id = $1 AND is_revoked = FALSE`).
  - [x] Atomic check in Postgres prevents race conditions when multiple parallel frontend requests attempt to refresh simultaneously.

- [x] **1.3 Fix Critical Bug in Logout Notification**
  - [x] Fixed `auth_service.go`: email notifications now receive valid user email addresses instead of user UUID.
  - [x] Stored user email in `AuthPrincipal` (populated in `auth_middleware.go` via JWT claims) so notification emails send to valid email addresses.

- [x] **1.4 Implement Missing Authentication & User Endpoints**
  - [x] `POST /api/v1/auth/logout-all`: Revoke all sessions belonging to the authenticated user.
  - [x] `POST /api/v1/auth/change-password`: Authenticated password change requiring `current_password` and `new_password`, revoking other sessions.
  - [x] `GET /api/v1/users/me`: Return authenticated user's profile (`id`, `email`, `role`, `created_at`, `email_verified`).
  - [x] `DELETE /api/v1/auth/sessions/:id`: RESTful endpoint to revoke a specific session.
  - [x] Route aliases: Support `/auth/register` (alias for `/auth/signup`) and `/auth/refresh` (alias for `/auth/refresh-session`) to match template specification.
  - [x] `GET /api/v1/admin/users`: Admin endpoint with pagination to list users and verify RBAC.
  - [x] `PATCH /api/v1/admin/users/:id/status`: Admin endpoint to activate/deactivate users.

- [x] **1.5 JWT Algorithm Hardening**
  - [x] Enforced allowed signing algorithm (`jwt.WithValidMethods([]string{"HS256"})`) in `token.go` and `auth_middleware.go` to prevent algorithm confusion/downgrade attacks.

---

### Phase 2: Security Protections & Middlewares (P0 - P1)

- [x] **2.1 Redis-Backed Distributed Rate Limiting Middleware**
  - [x] Created `internal/middleware/rate_limiter.go` using Redis sliding-window algorithm.
  - [x] Applied rate limits on sensitive endpoints:
    - Login (`/auth/login`): 10 attempts per minute per IP.
    - Registration (`/auth/signup` / `/auth/register`): 5 attempts per minute per IP.
    - Password Reset & OTP (`/auth/forgot-password`, `/auth/verify-email`): 5 attempts per minute per IP.
  - [x] Supported graceful fallback to in-memory rate limiting when Redis is unavailable.
  - [x] Returns standard `429 Too Many Requests` with `Retry-After` header.

- [x] **2.2 CORS Middleware**
  - [x] Created `internal/middleware/cors.go` with configurable origins, allowed methods, allowed headers, credentials support, and max age.
  - [x] Added CORS configuration variable `CORS_ALLOWED_ORIGINS` to `internal/config/config.go`, `.env`, and `.env.example`.

- [x] **2.3 Standardized Error Responses & Global Recovery**
  - [x] Replaced ad-hoc `c.JSON(403, ...)` in `rbac_examples_handler.go` with `apperrors.Write(c, apperrors.ErrForbidden)`.
  - [x] Added Gin `NoRoute` (404) and `NoMethod` (405) handlers in `router.go` returning consistent `errorEnvelope` JSON.
  - [x] Added custom panic recovery middleware returning standard `500 INTERNAL_SERVER_ERROR` JSON envelope without exposing stack traces.

- [x] **2.4 User Deactivation & Immediate Session Revocation**
  - [x] When a user is deactivated (`is_active = false`), all active sessions for that user are immediately revoked.
  - [x] Added `authMiddleware` check verifying `user.IsActive` so deactivated users cannot continue using existing short-lived access tokens.

---

### Phase 3: Operational Readiness & Observability (P1)

- [x] **3.1 Structured Logging with Sensitive Data Masking**
  - [x] Migrated logging to standard library `log/slog` with JSON output for production and text output for local dev.
  - [x] Created `MaskingHandler` ensuring passwords, access tokens, refresh tokens, and OTPs are never logged.
  - [x] Attached request IDs (`X-Request-ID`) to context and log records.

- [x] **3.2 Health & Readiness Probes**
  - [x] Implemented `GET /health` (liveness probe: returns 200 OK immediately).
  - [x] Implemented `GET /ready` (readiness probe: checks PostgreSQL ping and Redis ping; returns 200 OK if healthy, 503 Service Unavailable if any dependency fails).

- [x] **3.3 Security Audit Event System**
  - [x] Created structured audit logger for security-relevant actions:
    - Failed login attempts.
    - Password changes & resets.
    - Session revocations (`logout`, `logout-all`, remote session revoke).
    - Detected token reuse attacks (token hash, family ID, user ID).
    - User activation / deactivation admin actions.

- [x] **3.4 Startup Configuration Validation**
  - [x] Added `validate()` method in `internal/config/config.go`.
  - [x] Fail fast on startup with consolidated error reporting if:
    - `DATABASE_URL` is empty.
    - `REDIS_ADDR` is empty.
    - `JWT_SECRET` is empty or shorter than 32 characters.
    - `SMTP_HOST`, `SMTP_PORT`, or `SMTP_FROM` are empty when `IS_LOCAL_DEV_WITHOUT_SMTP` is false.
    - TTL values are negative or zero, or numeric parameters fail parsing.
  - [x] Unit tested in `internal/config/config_test.go`.

- [x] **3.5 Graceful Shutdown Coordination**
  - [x] Used `sync.WaitGroup` to coordinate shutdown between HTTP server and async email worker pool in `main.go`.
  - [x] Ensured pending email jobs in queue are processed before process exits.

- [x] **3.6 Database Connection Pool Tuning**
  - [x] Configured `SetConnMaxLifetime(time.Hour)` and `SetConnMaxIdleTime(15 * time.Minute)` in `internal/database/database.go`.

---

### Phase 4: Database Migrations & Tooling (P2)

- [x] **4.1 Down Migrations**
  - [x] Added `database/migrations/000001_create_users_table.down.sql`.
  - [x] Added `database/migrations/000002_create_sessions_table.down.sql`.
  - [x] Added `database/migrations/000003_add_session_family.up.sql` and `000003_add_session_family.down.sql`.
- [x] **4.2 CLI Migration Runner Improvements**
  - [x] Supported `-migrate down` and `-migrate drop` in `database/cmd/main.go`.
- [x] **4.3 Cleanups**
  - [x] Fixed typo in `.env.example`: `IS_LOCAL_DEV_WITHOUT_SMTP=false`.
  - [x] Updated `.gitignore` to include `.DS_Store`, build binaries, coverage files (`*.out`), and test scratch files.

---

### Phase 5: Containerization & Local Development (P1)

- [x] **5.1 Production Multi-Stage Dockerfile**
  - [x] Build stage with Go Alpine (compiles `server` and `migrate`).
  - [x] Lean runtime stage using `alpine:latest`.
  - [x] CA certificates, email templates, migrations, and entrypoint included.
- [x] **5.2 Docker Compose (`compose.yaml`)**
  - [x] Services:
    - `postgres`: PostgreSQL 16 with health check and persistent volume.
    - `redis`: Redis 7 with health check and persistent volume.
    - `mailpit`: Local SMTP and web UI (`axllent/mailpit:latest`).
    - `api`: GoAuth API with automatic migration execution and healthy dependency checks.
  - [x] Strictly loads all values from `.env` without default fallback values in compose.
- [x] **5.3 Developer Makefile**
  - [x] Targets: `build`, `run`, `migrate-up`, `migrate-down`, `seed`, `test`, `test-race`, `test-integration`, `lint`, `docker-up`, `docker-down`.

---

### Phase 6: Automated Testing Suite & CI (P0 - P1)

- [x] **6.1 Unit Tests**
  - [x] `internal/service/password_test.go`: Password hashing, comparison, bcrypt cost validation.
  - [x] `internal/service/token_test.go`: Access token generation, parsing, expiration, signature verification, algorithm mismatch rejections.
  - [x] `internal/middleware/auth_middleware_test.go`: Valid token, missing token, expired token, revoked session, malformed Bearer header, inactive user.
  - [x] `internal/middleware/rbac_middleware_test.go`: Role checks, multi-role allowance, forbidden access.
  - [x] `internal/middleware/rate_limiter_test.go`: Allowed requests within limit, 429 when exceeding threshold.
  - [x] `internal/service/auth_service_test.go`: Token family reuse detection, rotation, logout-all, password change.

- [x] **6.2 Security & Threat-Model Integration Tests**
  - [x] `tests/integration/auth_test.go`:
    - Full lifecycle: Signup -> Email Verification OTP -> Login -> Receive Tokens -> Protected Route.
    - Refresh Token Rotation: Call `/auth/refresh` -> Old token revoked, new tokens issued.
    - **Token Reuse Detection Test**: Re-submitting an already-rotated refresh token triggers immediate revocation of descendant session and returns 401.
    - **Concurrent Refresh Test**: Parallel refresh requests with the same token do not duplicate sessions or corrupt state.
    - Session Revocation & Logout All: Call `/auth/sessions`, revoke single session, call `/auth/logout-all`.
    - Health and Readiness Probes.
    - RBAC & Privilege Escalation: Non-admin trying to access admin endpoints returns 403.

- [x] **6.3 Continuous Integration (GitHub Actions)**
  - [x] Created `.github/workflows/ci.yml`:
    - Setup Go.
    - Spun up PostgreSQL & Redis service containers.
    - Run migrations.
    - Run unit and integration tests with race detector: `go test -v -race -coverprofile=coverage.out ./...`.
    - Run `govulncheck` to detect vulnerable Go dependencies.

---

### Phase 7: Reusable Template Documentation & Developer Experience (P0 - P1)

- [x] **7.1 Comprehensive Integration Guide in `README.md`**
  - [x] **Architecture overview**: Diagrams explaining Layered Architecture and Refresh Token Rotation with Token Family Reuse Detection.
  - [x] **How to reuse in another Gin monolith**: Step-by-step code snippets showing how to copy/import `internal/middleware`, configure `RequireAuth()` and `RequireRoles()`, and protect custom application routes.
  - [x] **Setup & Quickstart**: Docker Compose startup, environment configuration, database migration execution.
  - [x] **Security Design Decisions**: Explanation of why refresh tokens are hashed, how reuse detection prevents session hijacking, and why access tokens are short-lived.
  - [x] **Practical `curl` examples**: Clear commands for every endpoint (register, verify, login, refresh, access protected route, logout).

- [x] **7.2 OpenAPI / Swagger Documentation**
  - [x] Created `docs/openapi.yaml` documenting all request/response schemas, headers, error envelopes, and status codes.

- [x] **7.3 Runnable Monolith Example**
  - [x] Created `examples/monolith/main.go` demonstrating a host application importing GoAuth middleware, registering public and protected domain routes (e.g., `/api/v1/orders`), and performing ownership checks.

---

## 🎯 Verification & Definition of Done Checklist

- [x] `go test -v -race ./...` passes 100% without data races.
- [x] Fresh database migration works from scratch (`make migrate-up`).
- [x] Docker Compose boots Postgres, Redis, Mailpit, and GoAuth API seamlessly.
- [x] Refresh token reuse is detected and revokes the session family.
- [x] Rate limiter blocks brute force attempts on login/signup.
- [x] Structured logs contain zero plaintext credentials or tokens.
- [x] Another developer can follow `README.md` and protect an endpoint in a new Gin API in under 5 minutes.
