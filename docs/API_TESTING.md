# GoAuth — Complete API Endpoint Testing Guide 🧪

This document provides complete specification details and copy-paste-ready `curl` commands to test every endpoint in **GoAuth**, including full request/response schemas, status codes, authentication requirements, and an end-to-end testing walkthrough.

---

## 📋 Table of Contents

1. [Environment & Service Ports](#-environment--service-ports)
2. [End-to-End Testing Flow](#-end-to-end-testing-flow-recommended-order)
3. [Health & System Probes](#-1-health--system-probes)
4. [Public Authentication Endpoints](#-2-public-authentication-endpoints)
5. [Password Recovery Endpoints](#-3-password-recovery-endpoints)
6. [Protected User Endpoints](#-4-protected-user-endpoints)
7. [Session Management Endpoints](#-5-session-management-endpoints)
8. [Admin Management Endpoints (RBAC)](#-6-admin-management-endpoints-rbac)
9. [RBAC Example & Ownership Endpoints](#-7-rbac-example--ownership-endpoints)
10. [Special Security Test Scenarios](#-8-special-security-test-scenarios)
    - [Testing Token Reuse Detection (Replay Attack)](#testing-token-reuse-detection-replay-attack)
    - [Testing Rate Limiting (Brute Force Protection)](#testing-rate-limiting-brute-force-protection)
    - [Testing Deactivated User Immediate Revocation](#testing-deactivated-user-immediate-revocation)

---

## 🌐 Environment & Service Ports

Ensure your Docker stack is running before executing requests:
```bash
docker compose up -d --build
```

| Service | Host URL | Description |
| :--- | :--- | :--- |
| **GoAuth API** | `http://localhost:8080` | Main REST API server |
| **Mailpit Web UI** | `http://localhost:8026` | Web browser interface to view OTP verification emails |
| **Mailpit SMTP** | `localhost:1026` | Local SMTP port |
| **PostgreSQL** | `localhost:5432` | Database (`go_auth`) |
| **Redis** | `localhost:6380` | Cache & OTP store |

---

## 🔄 End-to-End Testing Flow (Recommended Order)

For a smooth test run, follow this sequence:
1. `GET /health` & `GET /ready` ➔ Confirm system is up.
2. `POST /api/v1/auth/signup` ➔ Register new account.
3. Open `http://localhost:8026` ➔ Copy the 6-digit OTP.
4. `POST /api/v1/auth/verify-email` ➔ Verify email.
5. `POST /api/v1/auth/login` ➔ Obtain Access & Refresh tokens.
6. `GET /api/v1/users/me` ➔ Access protected profile with Bearer token.
7. `POST /api/v1/auth/refresh` ➔ Rotate refresh token.
8. Re-run with the old token ➔ Verify Token Reuse Detection triggers 401.
9. `POST /api/v1/auth/logout-all` ➔ Terminate all user sessions.

---

## 🩺 1. Health & System Probes

### 1.1 Liveness Probe
- **Method & Route**: `GET /health`
- **Auth**: None (Public)
- **Description**: Returns 200 OK immediately if the HTTP engine is running.

```bash
curl -i http://localhost:8080/health
```

**Success Response (`200 OK`)**:
```json
{
  "status": "ok",
  "time": "2026-10-17T16:45:00Z"
}
```

---

### 1.2 Readiness Probe
- **Method & Route**: `GET /ready`
- **Auth**: None (Public)
- **Description**: Checks active connections to PostgreSQL and Redis. Returns 503 if any dependency is unreachable.

```bash
curl -i http://localhost:8080/ready
```

**Success Response (`200 OK`)**:
```json
{
  "status": "ready",
  "checks": {
    "database": "up",
    "redis": "up"
  },
  "time": "2026-10-17T16:45:00Z"
}
```

---

## 🔐 2. Public Authentication Endpoints

### 2.1 User Registration (Signup)
- **Method & Route**: `POST /api/v1/auth/signup` *(Alias: `POST /api/v1/auth/register`)*
- **Auth**: None (Public)
- **Rate Limit**: 5 requests / min / IP
- **Description**: Registers a new user account and dispatches a 6-digit OTP to their email.

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "StrongPassword123!"
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "message": "signup successful, please verify email"
}
```

**Error Responses**:
- `400 Bad Request`: `{"error":{"code":"VALIDATION_FAILED","message":"validation failed"}}`
- `409 Conflict`: `{"error":{"code":"USER_ALREADY_EXISTS","message":"user already exists"}}`
- `429 Too Many Requests`: `{"error":{"code":"RATE_LIMIT_EXCEEDED","message":"too many requests, please try again later"}}`

---

### 2.2 Verify Email OTP
- **Method & Route**: `POST /api/v1/auth/verify-email`
- **Auth**: None (Public)
- **Rate Limit**: 5 requests / min / IP
- **Description**: Verifies email address using the 6-digit OTP found in Mailpit (`http://localhost:8026`).

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "otp": "123456"
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "message": "email verified"
}
```

**Error Responses**:
- `400 Bad Request`: `{"error":{"code":"INVALID_OTP","message":"invalid otp"}}`

---

### 2.3 User Login
- **Method & Route**: `POST /api/v1/auth/login`
- **Auth**: None (Public)
- **Rate Limit**: 10 requests / min / IP
- **Description**: Verifies credentials and generates a short-lived Access Token (15m) and a persistent Refresh Token (30d).

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "StrongPassword123!"
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "u4W8sX...base64...",
  "user": {
    "id": "e2c90209-4676-4c4f-94a2-11a3ec95701a",
    "email": "alice@example.com",
    "role": "USER",
    "is_active": true,
    "is_email_verified": true
  }
}
```

**Quick Shell Storage**:
```bash
# Save tokens to terminal variables for subsequent requests:
export ACCESS_TOKEN="<access_token_from_login>"
export REFRESH_TOKEN="<refresh_token_from_login>"
```

**Error Responses**:
- `401 Unauthorized`: `{"error":{"code":"INVALID_CREDENTIALS","message":"invalid credentials"}}`
- `403 Forbidden`: `{"error":{"code":"EMAIL_NOT_VERIFIED","message":"email not verified"}}`
- `403 Forbidden`: `{"error":{"code":"FORBIDDEN","message":"forbidden"}}` (Account disabled)

---

### 2.4 Refresh & Rotate Session Token
- **Method & Route**: `POST /api/v1/auth/refresh` *(Alias: `POST /api/v1/auth/refresh-session`)*
- **Auth**: None (Requires valid unrevoked Refresh Token)
- **Description**: Atomically revokes the presented refresh token and issues a new access token and new rotated refresh token.

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "'"$REFRESH_TOKEN"'"
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1Ni...",
  "refresh_token": "newRotatedRefreshToken...",
  "user": {
    "id": "e2c90209-4676-4c4f-94a2-11a3ec95701a",
    "email": "alice@example.com",
    "role": "USER",
    "is_active": true,
    "is_email_verified": true
  }
}
```

**Error Responses**:
- `401 Unauthorized`: Token is expired, invalid, or belongs to an already revoked session (triggers Token Family Revocation).

---

## 🔑 3. Password Recovery Endpoints

### 3.1 Forgot Password Request
- **Method & Route**: `POST /api/v1/auth/forgot-password`
- **Auth**: None (Public)
- **Rate Limit**: 5 requests / min / IP
- **Description**: Dispatches a password reset OTP to the user's email if the account exists.

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com"
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "message": "if account exists, otp sent"
}
```

---

### 3.2 Verify Forgot Password OTP
- **Method & Route**: `POST /api/v1/auth/forgot-password/verify-otp`
- **Auth**: None (Public)
- **Description**: Validates the reset OTP and returns a single-use temporary `reset_token` (valid for 15 minutes).

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/forgot-password/verify-otp \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "otp": "654321"
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "reset_token": "temp_reset_token_string"
}
```

---

### 3.3 Complete Password Reset
- **Method & Route**: `POST /api/v1/auth/password-reset`
- **Auth**: None (Requires valid `reset_token`)
- **Description**: Resets the account password and revokes all active user sessions.

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/password-reset \
  -H "Content-Type: application/json" \
  -d '{
    "reset_token": "temp_reset_token_string",
    "new_password": "NewStrongPassword456!"
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "message": "password reset successful"
}
```

---

## 👤 4. Protected User Endpoints

All protected endpoints require the `Authorization: Bearer <ACCESS_TOKEN>` header.

### 4.1 Get Authenticated User Profile
- **Method & Route**: `GET /api/v1/users/me`
- **Auth**: Bearer JWT

```bash
curl -i http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Success Response (`200 OK`)**:
```json
{
  "id": "e2c90209-4676-4c4f-94a2-11a3ec95701a",
  "email": "alice@example.com",
  "role": "USER",
  "is_active": true,
  "is_email_verified": true
}
```

**Error Responses**:
- `401 Unauthorized`: Token missing, expired, tampered with, or corresponding session revoked.
- `403 Forbidden`: User account is deactivated (`is_active: false`).

---

### 4.2 Change Password (Authenticated)
- **Method & Route**: `POST /api/v1/auth/change-password`
- **Auth**: Bearer JWT
- **Description**: Verifies current password, updates hash, and revokes all other sessions.

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/change-password \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "StrongPassword123!",
    "new_password": "BrandNewPassword789!"
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "message": "password changed successfully"
}
```

---

## 📱 5. Session Management Endpoints

### 5.1 List Active Sessions
- **Method & Route**: `GET /api/v1/auth/sessions`
- **Auth**: Bearer JWT
- **Description**: Lists all active sessions for the authenticated user, identifying the current session via `is_current`.

```bash
curl -i http://localhost:8080/api/v1/auth/sessions \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Success Response (`200 OK`)**:
```json
{
  "sessions": [
    {
      "id": "a90184b2-e192-411a-82dc-304ba9f30e01",
      "ip_address": "127.0.0.1",
      "device": "macOS",
      "user_agent": "curl/8.7.1",
      "is_current": true,
      "created_at": "2026-10-17T16:30:00Z",
      "access_expires_at": "2026-10-17T16:45:00Z",
      "refresh_expires_at": "2026-11-16T16:30:00Z"
    }
  ]
}
```

---

### 5.2 Revoke Single Session by ID
- **Method & Route**: `DELETE /api/v1/auth/sessions/:id`
- **Auth**: Bearer JWT

```bash
curl -i -X DELETE http://localhost:8080/api/v1/auth/sessions/a90184b2-e192-411a-82dc-304ba9f30e01 \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Success Response (`200 OK`)**:
```json
{
  "message": "session revoked"
}
```

*(Note: Legacy alias `POST /api/v1/auth/revoke-session` with body `{"session_id":"..."}` is also supported).*

---

### 5.3 Logout Current Session
- **Method & Route**: `POST /api/v1/auth/logout`
- **Auth**: Bearer JWT
- **Description**: Revokes the current session and sends a security logout email notification.

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Success Response (`200 OK`)**:
```json
{
  "message": "logout successful"
}
```

---

### 5.4 Logout All Sessions
- **Method & Route**: `POST /api/v1/auth/logout-all`
- **Auth**: Bearer JWT
- **Description**: Revokes every active session belonging to the user across all devices.

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/logout-all \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**Success Response (`200 OK`)**:
```json
{
  "message": "logged out from all sessions"
}
```

---

## 🛡️ 6. Admin Management Endpoints (RBAC)

These endpoints require an Access Token with role `ADMIN`.

> [!TIP]
> The default seeded admin account is `admin@goauth.com` with password `Admin@123`.

```bash
# Login as Admin:
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@goauth.com","password":"Admin@123"}'
export ADMIN_TOKEN="<access_token_from_admin_login>"
```

### 6.1 List Users (Paginated)
- **Method & Route**: `GET /api/v1/admin/users?limit=20&offset=0`
- **Auth**: Bearer JWT (`ADMIN` role required)

```bash
curl -i http://localhost:8080/api/v1/admin/users?limit=10&offset=0 \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Success Response (`200 OK`)**:
```json
{
  "users": [
    {
      "id": "11111111-1111-1111-1111-111111111111",
      "email": "admin@goauth.com",
      "role": "ADMIN",
      "is_active": true,
      "is_email_verified": true
    },
    {
      "id": "e2c90209-4676-4c4f-94a2-11a3ec95701a",
      "email": "alice@example.com",
      "role": "USER",
      "is_active": true,
      "is_email_verified": true
    }
  ]
}
```

**Error Responses**:
- `403 Forbidden`: `{"error":{"code":"FORBIDDEN","message":"forbidden"}}` (If called with a non-admin token).

---

### 6.2 Update User Status (Activate / Deactivate)
- **Method & Route**: `PATCH /api/v1/admin/users/:id/status`
- **Auth**: Bearer JWT (`ADMIN` role required)
- **Description**: Enables or disables a user account. When deactivated (`is_active: false`), **all active sessions for that user are immediately revoked**.

```bash
curl -i -X PATCH http://localhost:8080/api/v1/admin/users/e2c90209-4676-4c4f-94a2-11a3ec95701a/status \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "is_active": false
  }'
```

**Success Response (`200 OK`)**:
```json
{
  "message": "user status updated"
}
```

---

## 🏛️ 7. RBAC Example & Ownership Endpoints

These routes demonstrate declarative role checking and fine-grained resource ownership:

### 7.1 Admin Only
- **Route**: `GET /admin-only`
- **Auth**: Requires `ADMIN` role.

```bash
curl -i http://localhost:8080/admin-only \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
*Response*: `{"message":"restricted: admin only"}`

---

### 7.2 User or Admin Shared
- **Route**: `GET /user-admin`
- **Auth**: Allows either `USER` or `ADMIN` role.

```bash
curl -i http://localhost:8080/user-admin \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```
*Response*: `{"message":"shared: both user and admin can access this"}`

---

### 7.3 User Details (Owner or Admin)
- **Route**: `GET /user-details/:id`
- **Auth**: Allowed if caller is the owner of `:id` OR has role `ADMIN`.

```bash
curl -i http://localhost:8080/user-details/e2c90209-4676-4c4f-94a2-11a3ec95701a \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```
*Response*: `{"data":"sensitive details for user ...","message":"access granted: owner or admin"}`

---

### 7.4 Private Vault (Strictly Owner Only)
- **Route**: `GET /user-private/:id`
- **Auth**: Allowed only if caller ID matches `:id`. Admins are forbidden.

```bash
curl -i http://localhost:8080/user-private/e2c90209-4676-4c4f-94a2-11a3ec95701a \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```
*Response*: `{"data":"private vault for user ...","message":"access granted: strictly owner only"}`

---

## 🔬 8. Special Security Test Scenarios

### Testing Token Reuse Detection (Replay Attack)
Test that reusing an already-rotated refresh token terminates the entire session family:

```bash
# 1. Login to get tokens
LOGIN_RES=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"StrongPassword123!"}')

RT_1=$(echo $LOGIN_RES | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)

# 2. Legitimate refresh: rotates RT_1 -> RT_2
REFRESH_RES=$(curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"'$RT_1'"}')

RT_2=$(echo $REFRESH_RES | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)

# 3. Attacker replays OLD RT_1:
curl -i -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"'$RT_1'"}'
# => Returns 401 Unauthorized! Security alert logged!

# 4. Verify that descendant token RT_2 has ALSO been revoked as a defense measure:
curl -i -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"'$RT_2'"}'
# => Returns 401 Unauthorized!
```

---

### Testing Rate Limiting (Brute Force Protection)
Execute 12 rapid login attempts within a loop to trigger `429 Too Many Requests`:

```bash
for i in {1..12}; do
  echo "Attempt $i:"
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@example.com","password":"bad_password"}'
done
```
*Output*: Requests 1–10 return `HTTP 401` (invalid credentials); requests 11–12 return `HTTP 429` with `Retry-After: 60`.

---

### Testing Deactivated User Immediate Revocation
Test that deactivating a user immediately invalidates their active short-lived access token:

```bash
# 1. Access protected route (Returns 200 OK)
curl -i http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# 2. Admin deactivates the user
curl -i -X PATCH http://localhost:8080/api/v1/admin/users/e2c90209-4676-4c4f-94a2-11a3ec95701a/status \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_active": false}'

# 3. User tries to access protected route with same token again:
curl -i http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# => Returns 403 Forbidden!
```
