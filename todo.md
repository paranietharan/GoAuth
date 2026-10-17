# GoAuth Template — Implementation Roadmap & TODO

This document tracks all missing features, security enhancements, testing requirements, and developer experience improvements needed to transform **GoAuth** into a production-grade, reusable authentication foundation for monolithic Go APIs, adhering to [`go_authentication_template_requirements.md`](./go_authentication_template_requirements.md).

---

## 📊 Requirements Gap Analysis Summary

| Category | Requirement Area | Status in Current Code | Priority |
| :--- | :--- | :--- | :--- |
| **Auth & Tokens** | Refresh-token rotation & reuse detection | ⚠️ Partial (Rotates, but **no** reuse detection or token family tracking) | **P0 (Critical)** |
| **Auth & Tokens** | Concurrent refresh request safety | ❌ Missing (Race conditions possible on parallel refreshes) | **P0 (Critical)** |
| **Auth & Tokens** | Missing endpoints (`logout-all`, `change-password`, `users/me`) | ❌ Missing from router and handlers | **P0 (Critical)** |
| **Auth & Tokens** | JWT Algorithm Hardening | ⚠️ Partial (Missing explicit algorithm whitelist on parsing) | **P1 (High)** |
| **Security** | Rate limiting (Login, Signup, Forgot-Password) | ❌ Missing (Zero rate limiting middleware) | **P0 (Critical)** |
| **Security** | CORS Configuration Middleware | ❌ Missing | **P1 (High)** |
| **Security** | Security Audit Logging (failures, reuse, revocations) | ❌ Missing (Uses standard unformatted logs) | **P1 (High)** |
| **Quality** | Unit & Integration Tests | ❌ Missing (0 test files in repo) | **P0 (Critical)** |
| **Quality** | CI/CD Pipeline (GitHub Actions) | ❌ Missing (`.github/workflows/ci.yml`) | **P1 (High)** |
| **Operations** | Structured logging (`slog`) with secret masking | ❌ Missing (Basic `log.Printf`) | **P1 (High)** |
| **Operations** | Health & Readiness endpoints (`/health`, `/ready`) | ❌ Missing (Database ping exists in repo, not exposed) | **P1 (High)** |
| **Operations** | Config validation at startup | ❌ Missing (Accepts invalid/insecure keys silently) | **P1 (High)** |
| **DevOps** | Dockerfile & Docker Compose | ❌ Missing | **P1 (High)** |
| **DevOps** | Database down migrations (`.down.sql`) | ❌ Missing | **P2 (Medium)** |
| **DevOps** | Makefile for developer workflows | ❌ Missing | **P2 (Medium)** |
| **Docs & DX** | Reusable integration guide in README | ⚠️ Incomplete (README has 12 lines) | **P0 (Critical)** |
| **Docs & DX** | OpenAPI / Swagger specification | ❌ Missing | **P1 (High)** |
| **Docs & DX** | Practical `curl` examples & monolithic integration example | ❌ Missing | **P1 (High)** |

---

## 🚀 Step-by-Step Implementation Roadmap

### Phase 1: Core Token Lifecycle, Reuse Detection & Bug Fixes (P0)

- [ ] **1.1 Implement Token Family & Refresh Token Reuse Detection**
  - [ ] Add `family_id UUID` column to `sessions` table (create migration `000003_add_session_family.up.sql` and `.down.sql`).
  - [ ] Update `model.Session` to include `FamilyID uuid.UUID`.
  - [ ] On login: Assign `family_id = session.id`.
  - [ ] On refresh: Carry forward `newSession.family_id = oldSession.family_id`.
  - [ ] In `authService.RefreshSession`:
    - Detect if presented refresh token belongs to an **already revoked** session.
    - If reuse is detected: Immediately revoke **all active sessions** within that `family_id` (or for that user), trigger a critical security audit event, and return `401 Unauthorized`.
    - Revoke descendant sessions to prevent token hijacking.
  - [ ] Store `family_id` in repository queries and session creation.

- [ ] **1.2 Handle Concurrent Refresh Requests Safely**
  - [ ] Implement atomic rotation check using database transaction / conditional update (`UPDATE sessions SET is_revoked = TRUE WHERE id = $1 AND is_revoked = FALSE`).
  - [ ] Add a short grace period (e.g. 5–10 seconds) or atomic lock in Redis/Postgres to prevent race conditions when multiple parallel frontend requests attempt to refresh simultaneously.

- [ ] **1.3 Fix Critical Bug in Logout Notification**
  - [ ] Fix `auth_service.go:246`: `s.emailSender.SendLogoutNotification(principal.UserID, ...)` is passing the user's UUID string instead of their email address.
  - [ ] Store user email in `AuthPrincipal` (populated in `auth_middleware.go` via JWT claims or DB lookup) so notification emails send to valid email addresses.

- [ ] **1.4 Implement Missing Authentication & User Endpoints**
  - [ ] `POST /api/v1/auth/logout-all`: Revoke all sessions belonging to the authenticated user.
  - [ ] `POST /api/v1/auth/change-password`: Authenticated password change requiring `current_password` and `new_password`, revoking other sessions.
  - [ ] `GET /api/v1/users/me`: Return authenticated user's profile (`id`, `email`, `role`, `created_at`, `email_verified`).
  - [ ] `DELETE /api/v1/auth/sessions/:id`: RESTful endpoint to revoke a specific session (replacing or aliasing `POST /auth/revoke-session`).
  - [ ] Route aliases: Support `/auth/register` (alias for `/auth/signup`) and `/auth/refresh` (alias for `/auth/refresh-session`) to match template specification.
  - [ ] `GET /api/v1/admin/users`: Admin endpoint with pagination to list users and verify RBAC.

- [ ] **1.5 JWT Algorithm Hardening**
  - [ ] Enforce allowed signing algorithm (`jwt.WithValidMethods([]string{"HS256"})`) in `token.go` and `auth_middleware.go` to prevent algorithm confusion/downgrade attacks.

---

### Phase 2: Security Protections & Middlewares (P0 - P1)

- [ ] **2.1 Redis-Backed Distributed Rate Limiting Middleware**
  - [ ] Create `internal/middleware/rate_limiter.go` using Redis sliding-window or token-bucket algorithm.
  - [ ] Apply strict rate limits on sensitive endpoints:
    - Login (`/auth/login`): e.g., 5 attempts per minute per IP/account.
    - Registration (`/auth/signup` / `/auth/register`): e.g., 3 attempts per minute per IP.
    - Password Reset & OTP (`/auth/forgot-password`, `/auth/verify-email`): e.g., 3 attempts per minute per IP/email.
  - [ ] Support graceful fallback to in-memory rate limiting if Redis is unavailable in local test environments.
  - [ ] Return standard `429 Too Many Requests` with `Retry-After` header.

- [ ] **2.2 CORS Middleware**
  - [ ] Create `internal/middleware/cors.go` with configurable origins, allowed methods (`GET, POST, PUT, DELETE, OPTIONS`), allowed headers (`Authorization, Content-Type`), credentials support, and max age.
  - [ ] Add CORS configuration variables to `internal/config/config.go` and `.env.example`.

- [ ] **2.3 Standardized Error Responses & Global Recovery**
  - [ ] Replace ad-hoc `c.JSON(403, ...)` in `rbac_examples_handler.go` with `apperrors.Write(c, apperrors.ErrForbidden)`.
  - [ ] Add Gin `NoRoute` (404) and `NoMethod` (405) handlers in `router.go` returning consistent `errorEnvelope` JSON.
  - [ ] Add custom panic recovery middleware returning standard `500 INTERNAL_SERVER_ERROR` JSON envelope without exposing stack traces.

- [ ] **2.4 User Deactivation & Immediate Session Revocation**
  - [ ] Ensure that when a user is deactivated (`is_active = false`), all active sessions for that user are immediately revoked.
  - [ ] Add `authMiddleware` check or cached active flag check so deactivated users cannot continue using existing short-lived access tokens.

---

### Phase 3: Operational Readiness & Observability (P1)

- [ ] **3.1 Structured Logging with Sensitive Data Masking**
  - [ ] Migrate logging to standard library `log/slog` with JSON output for production and text output for local dev.
  - [ ] Create log sanitization helper/middleware to ensure passwords, access tokens, refresh tokens, and OTPs are never logged.
  - [ ] Attach request IDs (`X-Request-ID`) to context and log records.

- [ ] **3.2 Health & Readiness Probes**
  - [ ] Implement `GET /health` (liveness probe: returns 200 OK immediately).
  - [ ] Implement `GET /ready` (readiness probe: checks PostgreSQL ping and Redis ping; returns 200 OK if healthy, 503 Service Unavailable if any dependency fails).

- [ ] **3.3 Security Audit Event System**
  - [ ] Create structured audit logger for security-relevant actions:
    - Failed login attempts (email, IP, User-Agent, failure reason).
    - Password changes & resets.
    - Session revocations (`logout`, `logout-all`, remote session revoke).
    - Detected token reuse attacks (token hash, user ID, IP).
    - Role elevation / admin actions.

- [x] **3.4 Startup Configuration Validation**
  - [x] Add `validate()` method in `internal/config/config.go`.
  - [x] Fail fast on startup with consolidated error reporting if:
    - `DATABASE_URL` is empty.
    - `REDIS_ADDR` is empty.
    - `JWT_SECRET` is empty or shorter than 32 characters.
    - `SMTP_HOST`, `SMTP_PORT`, or `SMTP_FROM` are empty when `IS_LOCAL_DEV_WITHOUT_SMTP` is false.
    - TTL values are negative or zero, or numeric parameters fail parsing.
  - [x] Unit tested in `internal/config/config_test.go`.

- [ ] **3.5 Graceful Shutdown Coordination**
  - [ ] Use `sync.WaitGroup` to coordinate shutdown between HTTP server and async email worker pool in `main.go`.
  - [ ] Ensure pending email jobs in queue are processed before process exits.

- [ ] **3.6 Database Connection Pool Tuning**
  - [ ] Configure `SetConnMaxLifetime` (e.g., 1 hour) and `SetConnMaxIdleTime` (e.g., 15 minutes) in `internal/database/database.go`.

---

### Phase 4: Database Migrations & Tooling (P2)

- [ ] **4.1 Down Migrations**
  - [ ] Add `database/migrations/000001_create_users_table.down.sql`.
  - [ ] Add `database/migrations/000002_create_sessions_table.down.sql`.
  - [ ] Add `database/migrations/000003_add_session_family.up.sql` and `000003_add_session_family.down.sql`.
- [ ] **4.2 CLI Migration Runner Improvements**
  - [ ] Support `-migrate down` and `-migrate version` in `database/cmd/main.go`.
- [ ] **4.3 Cleanups**
  - [ ] Fix typo in `.env.example`: `IS_LOCAL_DEV_WITHOUT_SMTP=flase` -> `false`.
  - [ ] Update `.gitignore` to include `.DS_Store`, build binaries, coverage files (`*.out`), and test scratch files.

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
- [ ] **5.3 Developer Makefile**
  - [ ] Targets: `build`, `run`, `migrate-up`, `migrate-down`, `seed`, `test`, `test-race`, `test-integration`, `lint`, `docker-up`, `docker-down`.

---

### Phase 6: Automated Testing Suite & CI (P0 - P1)

- [ ] **6.1 Unit Tests**
  - [ ] `internal/service/password_test.go`: Password hashing, comparison, bcrypt cost validation.
  - [ ] `internal/service/token_test.go`: Access token generation, parsing, expiration, signature verification, algorithm mismatch rejections.
  - [ ] `internal/middleware/auth_middleware_test.go`: Valid token, missing token, expired token, revoked session, malformed Bearer header.
  - [ ] `internal/middleware/rbac_middleware_test.go`: Role checks, multi-role allowance, forbidden access.
  - [ ] `internal/middleware/rate_limiter_test.go`: Allowed requests within limit, 429 when exceeding threshold.

- [ ] **6.2 Security & Threat-Model Integration Tests**
  - [ ] `tests/integration/auth_test.go`:
    - Full lifecycle: Signup -> Email Verification OTP -> Login -> Receive Tokens -> Protected Route.
    - Refresh Token Rotation: Call `/auth/refresh` -> Old token revoked, new tokens issued.
    - **Token Reuse Detection Test**: Re-submitting an already-rotated refresh token triggers immediate revocation of descendant session and returns 401.
    - **Concurrent Refresh Test**: Parallel refresh requests with the same token do not duplicate sessions or corrupt state.
    - Session Revocation: Call `/auth/sessions`, revoke single session, call `/auth/logout-all`.
    - Account Recovery: Forgot password OTP -> Temp token -> Reset password -> All prior sessions invalidated.
    - RBAC & Privilege Escalation: Non-admin trying to access admin endpoints returns 403.
    - Inactive Account: Deactivated user cannot log in or refresh tokens.

- [ ] **6.3 Continuous Integration (GitHub Actions)**
  - [ ] Create `.github/workflows/ci.yml`:
    - Setup Go.
    - Run linter (`golangci-lint`).
    - Spin up PostgreSQL & Redis service containers.
    - Run migrations.
    - Run unit and integration tests with race detector: `go test -v -race -coverprofile=coverage.out ./...`.
    - Run `govulncheck` to detect vulnerable Go dependencies.

---

### Phase 7: Reusable Template Documentation & Developer Experience (P0 - P1)

- [ ] **7.1 Comprehensive Integration Guide in `README.md`**
  - [ ] **Architecture overview**: Diagram explaining Handler -> Service -> Repository layers and JWT/Session model.
  - [ ] **How to reuse in another Gin monolith**: Step-by-step code snippets showing how to copy/import `internal/middleware`, configure `RequireAuth()` and `RequireRoles()`, and protect custom application routes.
  - [ ] **Setup & Quickstart**: Docker Compose one-liner startup, environment configuration, database migration execution.
  - [ ] **Security Design Decisions**: Explanation of why refresh tokens are hashed, how reuse detection prevents session hijacking, and why access tokens are short-lived.
  - [ ] **Practical `curl` examples**: Clear commands for every endpoint (register, verify, login, refresh, access protected route, logout).

- [ ] **7.2 OpenAPI / Swagger Documentation**
  - [ ] Create `docs/openapi.yaml` documenting all request/response schemas, headers, error envelopes, and status codes.
  - [ ] Provide instructions or endpoint to view Swagger UI.

- [ ] **7.3 Runnable Monolith Example**
  - [ ] Create `examples/monolith/main.go` demonstrating a host application importing GoAuth middleware, registering public and protected domain routes (e.g., `/api/v1/orders`), and performing ownership checks.

---

## 🎯 Verification & Definition of Done Checklist

When all steps above are completed, verify against Section 9 of `go_authentication_template_requirements.md`:

- [ ] `go test -v -race ./...` passes 100% without data races.
- [ ] Fresh database migration works from scratch (`make migrate-up -seed`).
- [ ] Docker Compose boots Postgres, Redis, Mailpit, and GoAuth API seamlessly.
- [ ] Refresh token reuse is detected and revokes the session family.
- [ ] Rate limiter blocks brute force attempts on login/signup.
- [ ] Structured logs contain zero plaintext credentials or tokens.
- [ ] Another developer can follow `README.md` and protect an endpoint in a new Gin API in under 5 minutes.
