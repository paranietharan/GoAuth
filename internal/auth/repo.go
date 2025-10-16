package auth

import (
	"GoAuth/internal/utils"
	"database/sql"
	"fmt"
	"log"
	"time"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *User) error {
	if user.ID == "" {
		user.ID = utils.GenerateUUID()
	}

	query := `
        INSERT INTO users (id, email, password_hash, first_name, last_name, role_id)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING created_at, updated_at
    `

	err := r.db.QueryRow(
		query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.RoleID,
	).Scan(&user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (r *UserRepository) GetByEmail(email string) (*User, error) {
	user := &User{}
	role := &Role{}
	query := `
		SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name, u.is_verified, u.is_active, u.role_id, u.created_at, u.updated_at,
		       r.id, r.name, r.description, r.created_at
		FROM users u
		LEFT JOIN roles r ON u.role_id = r.id
		WHERE u.email = $1
	`
	err := r.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsVerified,
		&user.IsActive,
		&user.RoleID,
		&user.CreatedAt,
		&user.UpdatedAt,
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	if role.ID != 0 {
		user.Role = role
	}

	// Load permissions
	if user.Role != nil {
		perms, err := r.getUserPermissions(user.ID)
		if err == nil {
			user.Permissions = perms
		}
	}

	return user, nil
}

func (r *UserRepository) GetByID(id string) (*User, error) {
	user := &User{}
	role := &Role{}
	query := `
		SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name, u.is_verified, u.is_active, u.role_id, u.created_at, u.updated_at,
		       r.id, r.name, r.description, r.created_at
		FROM users u
		LEFT JOIN roles r ON u.role_id = r.id
		WHERE u.id = $1
	`
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsVerified,
		&user.IsActive,
		&user.RoleID,
		&user.CreatedAt,
		&user.UpdatedAt,
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, err
	}

	if role.ID != 0 {
		user.Role = role
	}

	// Load permissions
	if user.Role != nil {
		perms, err := r.getUserPermissions(user.ID)
		if err == nil {
			user.Permissions = perms
		}
	}

	return user, nil
}

func (r *UserRepository) UpdateVerified(userID string, verified bool) error {
	query := `UPDATE users SET is_verified = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.Exec(query, verified, time.Now(), userID)
	return err
}

func (r *UserRepository) UpdatePassword(userID string, passwordHash string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err := r.db.Exec(query, passwordHash, time.Now(), userID)
	return err
}

func (r *UserRepository) GetAll() ([]User, error) {
	query := `
        SELECT u.id, u.email, u.password_hash, u.first_name, u.last_name, u.is_verified, u.is_active, u.role_id, u.created_at, u.updated_at,
               r.id, r.name, r.description, r.created_at
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        ORDER BY u.created_at DESC
    `
	rows, err := r.db.Query(query)
	if err != nil {
		log.Printf("Error fetching all users : %v\n", err)
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		user := User{}

		// Use temporary variables for nullable fields
		var roleID sql.NullInt64
		var role Role

		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.PasswordHash,
			&user.FirstName,
			&user.LastName,
			&user.IsVerified,
			&user.IsActive,
			&roleID, // Scan into NullInt64
			&user.CreatedAt,
			&user.UpdatedAt,
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Convert roleID back to *int if needed
		if roleID.Valid {
			roleIDInt := int(roleID.Int64)
			user.RoleID = &roleIDInt
		}

		// Only set Role if we have a valid role
		if role.ID != 0 {
			user.Role = &Role{
				ID:          role.ID,
				Name:        role.Name,
				Description: role.Description,
				CreatedAt:   role.CreatedAt,
			}
		}

		users = append(users, user)
	}
	return users, rows.Err()
}

func (r *UserRepository) Delete(userID string) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.Exec(query, userID)
	return err
}

func (r *UserRepository) getUserPermissions(userID string) ([]string, error) {
	query := `
		SELECT p.name FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN users u ON u.role_id = rp.role_id
		WHERE u.id = $1
	`
	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}
	return permissions, rows.Err()
}

func (r *UserRepository) GetRole(roleName string) (*Role, error) {
	query := `
        SELECT id, name, description, created_at
        FROM roles 
        WHERE name = $1
    `

	role := &Role{}
	err := r.db.QueryRow(query, roleName).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role not found: %s", roleName)
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return role, nil
}
