package dto

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email,max=320"`
}
