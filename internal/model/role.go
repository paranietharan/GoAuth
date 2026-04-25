package model

// Role defines application roles used by RBAC and JWT claims.
type Role string

const (
	RoleUser  Role = "USER"
	RoleAdmin Role = "ADMIN"
	RoleOwner Role = "OWNER"
)

func (r Role) IsValid() bool {
	switch r {
	case RoleUser, RoleAdmin, RoleOwner:
		return true
	default:
		return false
	}
}
