package auth

import (
	"database/sql"
	"fmt"
)

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

func (r *TokenRepository) RevokeAllUserRefreshTokens(userID string) error {
	query := `UPDATE refresh_tokens SET is_revoked = true WHERE user_id = $1`
	_, err := r.db.Exec(query, userID)
	return err
}
