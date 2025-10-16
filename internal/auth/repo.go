package auth

import (
	"database/sql"
	"fmt"
	"time"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *User) error {
	query := `
		INSERT INTO users (email, password_hash, first_name, last_name, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at, is_verified, is_active
	`
	return r.db.QueryRow(
		query,
		user.Email,
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.Role,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt, &user.IsVerified, &user.IsActive)
}

func (r *UserRepository) GetByEmail(email string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, email, password_hash, first_name, last_name, is_verified, is_active, role, created_at, updated_at
		FROM users WHERE email = $1
	`
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsVerified,
		&user.IsActive,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	return user, err
}

func (r *UserRepository) GetByID(id int) (*User, error) {
	user := &User{}
	query := `
		SELECT id, email, password_hash, first_name, last_name, is_verified, is_active, role, created_at, updated_at
		FROM users WHERE id = $1
	`
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsVerified,
		&user.IsActive,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	return user, err
}

func (r *UserRepository) UpdateVerified(userID int, verified bool) error {
	query := `UPDATE users SET is_verified = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.Exec(query, verified, time.Now(), userID)
	return err
}

func (r *UserRepository) UpdatePassword(userID int, passwordHash string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.Exec(query, passwordHash, time.Now(), userID)
	return err
}

// TokenRepository handles token operations
type TokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) Create(token *Token) error {
	query := `
		INSERT INTO tokens (user_id, token, token_type, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, is_used
	`
	return r.db.QueryRow(
		query,
		token.UserID,
		token.Token,
		token.TokenType,
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt, &token.IsUsed)
}

func (r *TokenRepository) GetByToken(tokenStr string) (*Token, error) {
	token := &Token{}
	query := `
		SELECT id, user_id, token, token_type, expires_at, is_used, created_at
		FROM tokens WHERE token = $1
	`
	err := r.db.QueryRow(query, tokenStr).Scan(
		&token.ID,
		&token.UserID,
		&token.Token,
		&token.TokenType,
		&token.ExpiresAt,
		&token.IsUsed,
		&token.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("token not found")
	}
	return token, err
}

func (r *TokenRepository) MarkAsUsed(tokenID int) error {
	query := `UPDATE tokens SET is_used = true WHERE id = $1`
	_, err := r.db.Exec(query, tokenID)
	return err
}

func (r *TokenRepository) CreateRefreshToken(rt *RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, is_revoked
	`
	return r.db.QueryRow(
		query,
		rt.UserID,
		rt.Token,
		rt.ExpiresAt,
	).Scan(&rt.ID, &rt.CreatedAt, &rt.IsRevoked)
}

func (r *TokenRepository) GetRefreshToken(tokenStr string) (*RefreshToken, error) {
	rt := &RefreshToken{}
	query := `
		SELECT id, user_id, token, expires_at, is_revoked, created_at
		FROM refresh_tokens WHERE token = $1
	`
	err := r.db.QueryRow(query, tokenStr).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.Token,
		&rt.ExpiresAt,
		&rt.IsRevoked,
		&rt.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("refresh token not found")
	}
	return rt, err
}

func (r *TokenRepository) RevokeRefreshToken(tokenID int) error {
	query := `UPDATE refresh_tokens SET is_revoked = true WHERE id = $1`
	_, err := r.db.Exec(query, tokenID)
	return err
}

func (r *TokenRepository) RevokeAllUserRefreshTokens(userID int) error {
	query := `UPDATE refresh_tokens SET is_revoked = true WHERE user_id = $1`
	_, err := r.db.Exec(query, userID)
	return err
}
