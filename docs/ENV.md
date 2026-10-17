# Environment Variables Reference

This document lists all environment variables used by **GoAuth** across local development, Docker Compose, and production deployments.

---

## 1. Application & Server Configuration

| Variable | Description | Example Value |
| :--- | :--- | :--- |
| `PORT` | HTTP port the Go application server listens on. | `8080` |
| `JWT_SECRET` | Secret key used to sign and verify HMAC-SHA256 access tokens. | `your-secure-jwt-secret-key-change-this` |
| `AUTO_MIGRATE` | Whether to automatically apply database migrations and seed data on container startup. | `true` |

---

## 2. Database Configuration (PostgreSQL)

| Variable | Description | Example Value |
| :--- | :--- | :--- |
| `POSTGRES_USER` | PostgreSQL username. | `postgres` |
| `POSTGRES_PASSWORD` | PostgreSQL user password. | `root` |
| `POSTGRES_DB` | PostgreSQL database name. | `go_auth` |
| `POSTGRES_PORT` | Host port mapped to PostgreSQL container (`5432`). | `5432` |
| `DATABASE_URL` | Full PostgreSQL connection string used by the Go application. | `postgres://postgres:root@postgres:5432/go_auth?sslmode=disable` |

---

## 3. Redis Configuration

| Variable | Description | Example Value |
| :--- | :--- | :--- |
| `REDIS_ADDR` | Host and port address for the Redis server. | `redis:6379` |
| `REDIS_PORT` | Host port mapped to the Redis container (`6379`). | `6380` |
| `REDIS_PASSWORD` | Authentication password for Redis (leave empty if none). | *(empty)* |
| `REDIS_DB` | Redis logical database index number. | `0` |

---

## 4. Mailpit Configuration (Local Testing)

| Variable | Description | Example Value |
| :--- | :--- | :--- |
| `MAILPIT_SMTP_PORT` | Host port mapped to Mailpit SMTP server (`1025`). | `1026` |
| `MAILPIT_UI_PORT` | Host port mapped to Mailpit webmail interface (`8025`). | `8026` |

---

## 5. SMTP Email Delivery Configuration

| Variable | Description | Example Value |
| :--- | :--- | :--- |
| `IS_LOCAL_DEV_WITHOUT_SMTP` | When set to `true`, prints emails to console instead of sending via SMTP. | `false` |
| `SMTP_HOST` | Hostname of the outgoing SMTP server (`mailpit` in Docker, or e.g. `smtp.gmail.com`). | `mailpit` |
| `SMTP_PORT` | Port number for the SMTP server (`1025` for Mailpit, `587` for TLS SMTP). | `1025` |
| `SMTP_USER` | Username / email address for authenticating with SMTP (leave empty for Mailpit). | `your-email@gmail.com` |
| `SMTP_PASSWORD` | Password or app password for SMTP authentication (leave empty for Mailpit). | `your-app-password` |
| `SMTP_FROM` | Sender address appearing in outgoing email `From:` headers. | `noreply@goauth.local` |

---

## 6. Authentication & Security Strategy

| Variable | Description | Example Value |
| :--- | :--- | :--- |
| `BCRYPT_COST` | Hashing work factor for bcrypt password encryption (range: `10`–`14`). | `12` |
| `ACCESS_TOKEN_TTL_MINUTES` | Lifetime of short-lived JWT access tokens in minutes. | `15` |
| `REFRESH_TOKEN_TTL_DAYS` | Lifetime of rotating refresh tokens and login sessions in days. | `30` |
| `EMAIL_VERIFICATION_TTL_MINUTES` | Validity period of email verification OTPs in minutes. | `10` |
| `FORGOT_PASSWORD_OTP_TTL_MINUTES` | Validity period of forgot-password OTPs in minutes. | `10` |
| `RESET_TEMP_TOKEN_TTL_MINUTES` | Validity period of temporary password-reset tokens in minutes. | `15` |

---

## 7. Default Seed Data

| Variable | Description | Example Value |
| :--- | :--- | :--- |
| `SEED_ADMIN_EMAIL` | Email address for initial bootstrap administrator account. | `admin@goauth.com` |
| `SEED_ADMIN_PASSWORD` | Password for initial bootstrap administrator account. | `Admin@123` |
