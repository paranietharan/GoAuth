package dto

type PasswordResetRequest struct {
	Email       string `json:"email" validate:"required,email,max=320"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=72"`
	TempToken   string `json:"temp_token" validate:"required"`
}
