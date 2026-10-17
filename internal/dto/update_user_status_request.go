package dto

type UpdateUserStatusRequest struct {
	IsActive *bool `json:"is_active" validate:"required"`
}
