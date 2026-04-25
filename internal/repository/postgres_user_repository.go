package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"GoAuth/internal/model"

	"github.com/google/uuid"
)

type PostgresUserRepository struct {
	db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) Create(ctx context.Context, user *model.User) error {
	query := `
		INSERT INTO users (
			id, email, password_hash, role, is_active, is_email_verified,
			email_verified_at, last_login_at, last_login_ip, last_login_user_agent,
			last_login_device, created_at, updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.Role,
		user.IsActive,
		user.IsEmailVerified,
		user.EmailVerifiedAt,
		user.LastLoginAt,
		user.LastLoginIP,
		user.LastLoginUserAgent,
		user.LastLoginDevice,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `
		SELECT id, email, password_hash, role, is_active, is_email_verified,
			email_verified_at, last_login_at, last_login_ip::text,
			last_login_user_agent, last_login_device, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	return r.scanOne(ctx, query, email)
}

func (r *PostgresUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	query := `
		SELECT id, email, password_hash, role, is_active, is_email_verified,
			email_verified_at, last_login_at, last_login_ip::text,
			last_login_user_agent, last_login_device, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	return r.scanOne(ctx, query, id)
}

func (r *PostgresUserRepository) IsEmailTaken(ctx context.Context, email string) (bool, error) {
	const query = `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
	var exists bool
	if err := r.db.QueryRowContext(ctx, query, email).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

func (r *PostgresUserRepository) MarkEmailVerified(ctx context.Context, userID uuid.UUID, verifiedAt time.Time) error {
	const query = `
		UPDATE users
		SET is_email_verified = TRUE, email_verified_at = $2, updated_at = NOW()
		WHERE id = $1
	`
	res, err := r.db.ExecContext(ctx, query, userID, verifiedAt)
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
	return nil
}

func (r *PostgresUserRepository) UpdatePasswordHash(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	const query = `
		UPDATE users
		SET password_hash = $2, updated_at = NOW()
		WHERE id = $1
	`
	res, err := r.db.ExecContext(ctx, query, userID, passwordHash)
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
	return nil
}

func (r *PostgresUserRepository) scanOne(ctx context.Context, query string, arg any) (*model.User, error) {
	user := &model.User{}
	var emailVerifiedAt sql.NullTime
	var lastLoginAt sql.NullTime
	var lastLoginIP sql.NullString
	var lastLoginUA sql.NullString
	var lastLoginDevice sql.NullString
	var role string

	err := r.db.QueryRowContext(ctx, query, arg).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&role,
		&user.IsActive,
		&user.IsEmailVerified,
		&emailVerifiedAt,
		&lastLoginAt,
		&lastLoginIP,
		&lastLoginUA,
		&lastLoginDevice,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	user.Role = model.Role(role)
	if !user.Role.IsValid() {
		return nil, errors.New("invalid role value in database")
	}
	if emailVerifiedAt.Valid {
		user.EmailVerifiedAt = &emailVerifiedAt.Time
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	if lastLoginIP.Valid {
		v := lastLoginIP.String
		user.LastLoginIP = &v
	}
	if lastLoginUA.Valid {
		v := lastLoginUA.String
		user.LastLoginUserAgent = &v
	}
	if lastLoginDevice.Valid {
		v := lastLoginDevice.String
		user.LastLoginDevice = &v
	}
	return user, nil
}
