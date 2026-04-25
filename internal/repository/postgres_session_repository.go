package repository

import (
	"context"
	"database/sql"

	"GoAuth/internal/model"

	"github.com/google/uuid"
)

type PostgresSessionRepository struct {
	db *sql.DB
}

func NewPostgresSessionRepository(db *sql.DB) *PostgresSessionRepository {
	return &PostgresSessionRepository{db: db}
}

func (r *PostgresSessionRepository) Create(ctx context.Context, session *model.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, access_token_hash, refresh_token_hash,
			access_expires_at, refresh_expires_at, is_revoked, ip_address,
			user_agent, device, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`
	_, err := r.db.ExecContext(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.AccessTokenHash,
		session.RefreshTokenHash,
		session.AccessExpiresAt,
		session.RefreshExpiresAt,
		session.IsRevoked,
		session.IPAddress,
		session.UserAgent,
		session.Device,
		session.CreatedAt,
		session.UpdatedAt,
	)
	return err
}

func (r *PostgresSessionRepository) CreateWithLoginMetadata(ctx context.Context, session *model.Session, metadata LoginMetadata) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	insertSession := `
		INSERT INTO sessions (
			id, user_id, access_token_hash, refresh_token_hash,
			access_expires_at, refresh_expires_at, is_revoked, ip_address,
			user_agent, device, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
	`
	if _, err := tx.ExecContext(
		ctx,
		insertSession,
		session.ID,
		session.UserID,
		session.AccessTokenHash,
		session.RefreshTokenHash,
		session.AccessExpiresAt,
		session.RefreshExpiresAt,
		session.IsRevoked,
		session.IPAddress,
		session.UserAgent,
		session.Device,
		session.CreatedAt,
		session.UpdatedAt,
	); err != nil {
		return err
	}

	updateUser := `
		UPDATE users
		SET last_login_at = $2,
			last_login_ip = $3,
			last_login_user_agent = $4,
			last_login_device = $5,
			updated_at = NOW()
		WHERE id = $1
	`
	res, err := tx.ExecContext(ctx, updateUser, metadata.UserID, metadata.At, metadata.IPAddress, metadata.UserAgent, metadata.Device)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return tx.Commit()
}

func (r *PostgresSessionRepository) GetByAccessTokenHash(ctx context.Context, accessTokenHash string) (*model.Session, error) {
	query := `
		SELECT id, user_id, access_token_hash, refresh_token_hash, access_expires_at,
			refresh_expires_at, is_revoked, ip_address::text, user_agent, device, created_at, updated_at
		FROM sessions
		WHERE access_token_hash = $1
	`
	return r.scanOne(ctx, query, accessTokenHash)
}

func (r *PostgresSessionRepository) GetByRefreshTokenHash(ctx context.Context, refreshTokenHash string) (*model.Session, error) {
	query := `
		SELECT id, user_id, access_token_hash, refresh_token_hash, access_expires_at,
			refresh_expires_at, is_revoked, ip_address::text, user_agent, device, created_at, updated_at
		FROM sessions
		WHERE refresh_token_hash = $1
	`
	return r.scanOne(ctx, query, refreshTokenHash)
}

func (r *PostgresSessionRepository) GetByID(ctx context.Context, sessionID uuid.UUID) (*model.Session, error) {
	query := `
		SELECT id, user_id, access_token_hash, refresh_token_hash, access_expires_at,
			refresh_expires_at, is_revoked, ip_address::text, user_agent, device, created_at, updated_at
		FROM sessions
		WHERE id = $1
	`
	return r.scanOne(ctx, query, sessionID)
}

func (r *PostgresSessionRepository) ListActiveByUserID(ctx context.Context, userID uuid.UUID) ([]model.Session, error) {
	query := `
		SELECT id, user_id, access_token_hash, refresh_token_hash, access_expires_at,
			refresh_expires_at, is_revoked, ip_address::text, user_agent, device, created_at, updated_at
		FROM sessions
		WHERE user_id = $1 AND is_revoked = FALSE AND refresh_expires_at > NOW()
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := make([]model.Session, 0)
	for rows.Next() {
		s, err := scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *PostgresSessionRepository) RevokeByID(ctx context.Context, sessionID uuid.UUID) error {
	const query = `UPDATE sessions SET is_revoked = TRUE, updated_at = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, sessionID)
	return err
}

func (r *PostgresSessionRepository) RevokeByIDForUser(ctx context.Context, sessionID, userID uuid.UUID) (bool, error) {
	const query = `
		UPDATE sessions
		SET is_revoked = TRUE, updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND is_revoked = FALSE
	`
	res, err := r.db.ExecContext(ctx, query, sessionID, userID)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (r *PostgresSessionRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	const query = `
		UPDATE sessions
		SET is_revoked = TRUE, updated_at = NOW()
		WHERE user_id = $1 AND is_revoked = FALSE
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *PostgresSessionRepository) scanOne(ctx context.Context, query string, arg any) (*model.Session, error) {
	row := r.db.QueryRowContext(ctx, query, arg)
	return scanSessionRow(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanSessionRow(s scanner) (*model.Session, error) {
	session := &model.Session{}
	var ipAddress sql.NullString
	var userAgent sql.NullString
	var device sql.NullString

	err := s.Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenHash,
		&session.RefreshTokenHash,
		&session.AccessExpiresAt,
		&session.RefreshExpiresAt,
		&session.IsRevoked,
		&ipAddress,
		&userAgent,
		&device,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if ipAddress.Valid {
		v := ipAddress.String
		session.IPAddress = &v
	}
	if userAgent.Valid {
		v := userAgent.String
		session.UserAgent = &v
	}
	if device.Valid {
		v := device.String
		session.Device = &v
	}
	return session, nil
}
