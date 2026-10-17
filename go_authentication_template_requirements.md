# Go Authentication Template: Project Requirements

## 1. Project Goal

Build a reusable Go authentication template that developers can integrate into new Go applications without rewriting security-critical authentication code.

The project should demonstrate:

- Secure authentication and authorization
- Reusable Go application architecture
- Session and token lifecycle management
- Security-focused testing
- Developer-friendly setup and documentation
- Production-oriented operational practices

**Important:** A basic login/register API with JWT generation is too common to significantly strengthen a software engineering CV. The project becomes more valuable when it demonstrates secure token lifecycle management, authorization, thorough tests, and a good developer experience.

---

## 2. Essential Features

### 2.1 Secure Authentication

- [ ] User registration
- [ ] User login
- [ ] Password hashing using Argon2id or bcrypt
- [ ] Short-lived access tokens
- [ ] Refresh-token rotation
- [ ] Refresh-token revocation
- [ ] Logout that invalidates the relevant refresh session
- [ ] Generic login errors that do not reveal whether an account exists

### 2.2 Authorization and Access Control

- [ ] Role-based access control (RBAC)
- [ ] Middleware for protecting routes
- [ ] Ownership or permission checks where resources require them
- [ ] Consistent `401 Unauthorized` and `403 Forbidden` responses

**Remember:** Authentication answers *who the user is*. Authorization answers *what the user is allowed to do*.

### 2.3 Session and Token Management

- [ ] Store refresh tokens as hashes instead of reusable plaintext secrets
- [ ] Track sessions per device or login
- [ ] Revoke individual sessions
- [ ] Revoke all sessions belonging to a user
- [ ] Detect reuse of rotated refresh tokens
- [ ] Revoke the affected token family when reuse is detected
- [ ] Store token expiry and session metadata in PostgreSQL

### 2.4 Security Protections

- [ ] Rate-limit login, registration, and password-reset endpoints
- [ ] Validate input
- [ ] Use parameterized SQL queries
- [ ] Configure CORS securely
- [ ] Implement CSRF protection when using cookie-based authentication
- [ ] Set secure cookie attributes where cookies are used: `HttpOnly`, `Secure`, and an appropriate `SameSite` policy
- [ ] Load secrets from environment variables or a secret manager
- [ ] Never commit secrets to the repository

Apply protections based on the selected token transport and deployment model. Cookie-based authentication and bearer-token authentication have different security requirements.

### 2.5 Account Lifecycle

- [ ] Email verification
- [ ] Forgot-password workflow
- [ ] Password-reset workflow
- [ ] Expiring, single-use verification and reset tokens
- [ ] Password change with reauthentication or current-session invalidation
- [ ] Account disablement policy

---

## 3. Features That Make the Project Stand Out

### 3.1 Reusable Go Architecture

- [ ] Separate HTTP handlers, services, repositories, and middleware
- [ ] Use interfaces at appropriate boundaries to support testing
- [ ] Use dependency injection without unnecessary frameworks
- [ ] Establish consistent error handling and response formats
- [ ] Validate configuration at startup

Avoid creating abstractions that do not solve a real problem. The architecture should be reusable without becoming needlessly complicated.

### 3.2 Developer-Friendly Integration

- [ ] Document how to register authentication middleware in an existing Gin application
- [ ] Make database connection and token settings configurable
- [ ] Provide database migrations
- [ ] Include a `.env.example` with safe placeholder values
- [ ] Provide a runnable example API with public and protected endpoints
- [ ] Publish OpenAPI/Swagger documentation
- [ ] Include practical `curl` examples

### 3.3 Testing and Reliability

- [ ] Unit tests for password handling
- [ ] Unit tests for token validation
- [ ] Unit tests for authorization
- [ ] Integration tests using PostgreSQL
- [ ] Test expired tokens
- [ ] Test revoked sessions
- [ ] Test concurrent refresh requests
- [ ] Test privilege-escalation attempts
- [ ] Run tests and linting in CI
- [ ] Run Go race detection where appropriate
- [ ] Check dependencies for known vulnerabilities

Prefer disposable test databases or containers for integration tests so tests do not depend on a developer's local database state.

### 3.4 Operational Readiness

- [ ] Structured logging with sensitive data redacted
- [ ] Health endpoint
- [ ] Readiness endpoint
- [ ] Graceful shutdown
- [ ] Database connection pooling
- [ ] Sensible request and database timeouts
- [ ] Security audit events for login failures, password changes, and session revocation

Never log passwords, access tokens, refresh tokens, password-reset tokens, or other secrets.

---

## 4. Optional Advanced Features

Add these after the core implementation is secure and tested.

| Feature | Value | Recommendation |
|---|---|---|
| Refresh-token rotation and reuse detection | Very high | Essential |
| RBAC and authorization middleware | Very high | Essential |
| Comprehensive security tests | Very high | Essential |
| TOTP-based multi-factor authentication (MFA) | High | Add after the core is secure |
| OAuth 2.0 / OpenID Connect login | High | Good second milestone |
| Multi-tenant authentication | High for SaaS roles | Add if implemented properly |
| Redis-backed distributed rate limiting | High | Useful when the deployment requires it |
| Passkeys / WebAuthn | High but complex | Optional advanced milestone |
| GraphQL authentication | Low for a general Go template | Skip unless targeting GraphQL |
| Separate microservices just for authentication | Often negative | Avoid unnecessary complexity |

### Suggested implementation order

1. Secure core authentication
2. Refresh-token lifecycle and session management
3. RBAC and protected routes
4. Account recovery and email verification
5. Automated security and integration tests
6. Documentation, Docker, and CI
7. MFA or OAuth/OIDC as an advanced milestone

---

## 5. Recommended Architecture

Start with a **modular Go application**, not several microservices. A template should be easy to understand, integrate, test, and operate.

```text
HTTP API (Gin)
    |
    v
Middleware
  - Authentication
  - Authorization
  - Rate limiting
  - Request validation
    |
    v
Service Layer
  - Credentials
  - Token lifecycle
  - Session management
  - Account recovery
    |
    v
Repositories
    |
    +--------------------+
    |                    |
    v                    v
PostgreSQL             Redis (optional)
- Users                - Distributed rate limits
- Sessions             - Temporary state where useful
- Token hashes
- Roles
```

### Recommended stack

- **Language:** Go
- **HTTP framework:** Gin
- **Database:** PostgreSQL
- **Database access:** `pgx` with SQL migrations, or `sqlc` for type-safe generated queries
- **Authentication:** JWT access tokens with opaque, rotating refresh tokens
- **Testing:** Go testing package and integration tests
- **Infrastructure:** Docker Compose and GitHub Actions
- **Documentation:** OpenAPI

Redis is not required for the first version. Add it only when it solves a concrete requirement, such as distributed rate limiting.

### Important token design notes

- Keep access tokens short-lived.
- Validate the token signature, permitted algorithm, issuer, audience where applicable, and expiry.
- Do not assume a validly signed token grants access to every resource; authorization must still be checked.
- Store refresh tokens as hashes and rotate them on use.
- Design refresh-token rotation to handle concurrent requests safely.
- Revoke the relevant session or token family when reuse is detected.

---

## 6. Suggested API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/auth/register` | Create an account |
| `POST` | `/auth/login` | Authenticate credentials |
| `POST` | `/auth/refresh` | Rotate a refresh token |
| `POST` | `/auth/logout` | Revoke the current session |
| `POST` | `/auth/logout-all` | Revoke all sessions for a user |
| `POST` | `/auth/forgot-password` | Initiate password recovery |
| `POST` | `/auth/reset-password` | Complete password reset |
| `POST` | `/auth/verify-email` | Verify an email address |
| `GET` | `/auth/sessions` | List active sessions |
| `DELETE` | `/auth/sessions/:id` | Revoke a specific session |
| `GET` | `/users/me` | Return the authenticated user |
| `GET` | `/admin/users` | Example admin-only endpoint |

MFA endpoints can be added later.

---

## 7. Repository and Developer Experience

A possible project layout:

```text
goauth/
├── cmd/
│   └── api/
│       └── main.go
├── internal/
│   ├── config/
│   ├── http/
│   │   ├── handlers/
│   │   ├── middleware/
│   │   └── routes/
│   ├── auth/
│   │   ├── service.go
│   │   ├── tokens.go
│   │   └── password.go
│   ├── user/
│   │   ├── service.go
│   │   └── repository.go
│   ├── session/
│   └── database/
├── migrations/
├── docs/
├── examples/
├── tests/
├── Dockerfile
├── compose.yaml
├── Makefile
├── .env.example
├── .gitignore
├── go.mod
└── README.md
```

Treat this as a starting point, not a rigid rule. Keep the layout appropriate to the project's size and avoid packages that exist only to satisfy a diagram.

The README should explain:

- What the template does and does not provide
- Prerequisites and setup instructions
- Environment variables
- Database migrations
- How to run tests
- How to run the service with Docker Compose
- Example requests and responses
- How to protect an endpoint in another Gin application
- Token/session lifecycle
- Security decisions and limitations

---

## 8. CV-Worthy Project Description

Use the following only after implementing and verifying the corresponding features.

**GoAuth — Reusable Go Authentication Template**  
*Go, Gin, PostgreSQL, Redis, Docker, GitHub Actions*

- Built a reusable authentication foundation for Go APIs with secure password hashing, JWT access tokens, rotating refresh sessions, and session revocation.
- Implemented role-based authorization middleware, account recovery workflows, and protections against brute-force login attempts.
- Added automated unit and integration tests, database migrations, Docker-based local development, and CI security checks.

Remove any claim that you have not actually implemented and tested.

---

## 9. Definition of Done

Before treating the project as complete, verify each milestone.

### Core security

- [ ] Registration and login work
- [ ] Passwords are hashed securely
- [ ] Access-token validation rejects invalid and expired tokens
- [ ] Refresh tokens rotate and can be revoked
- [ ] Reuse detection behaves as intended
- [ ] RBAC prevents unauthorized access
- [ ] Password-reset and verification tokens expire and cannot be reused

### Quality

- [ ] Unit tests pass
- [ ] Integration tests pass against PostgreSQL
- [ ] Security-focused negative tests exist
- [ ] Race detection has been run where appropriate
- [ ] CI runs tests and linting
- [ ] No secrets are committed
- [ ] Logs do not expose sensitive tokens or credentials

### Reusability

- [ ] A new developer can start the project from the README
- [ ] Database migrations work from a clean database
- [ ] Example protected and public endpoints work
- [ ] OpenAPI documentation and request examples are available
- [ ] Configuration is validated at startup

Completing the checklist does not automatically prove the system is production-secure. Review the threat model, implementation, dependencies, and deployment configuration before making that claim.

---

## 10. Final Recommendation

Build the project if you are willing to go beyond basic JWT login and registration.

Prioritize these five differentiators:

1. Refresh-token rotation, revocation, and reuse detection
2. Secure session management
3. RBAC and authorization middleware
4. Meaningful automated tests, including failure and security cases
5. A genuinely reusable developer experience with documentation and examples

These capabilities complement your existing Go backend and distributed-systems projects. Avoid adding microservices or technologies merely to make the architecture look more complex.

**Target outcome:** a small, well-designed, thoroughly tested authentication template that another developer can genuinely reuse—not a large boilerplate repository full of features you cannot confidently explain in an interview.
