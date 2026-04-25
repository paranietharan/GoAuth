package dto

type VerifyEmailRequest struct {
	Email string `json:"email" validate:"required,email,max=320"`
	OTP   string `json:"otp" validate:"required,len=6,numeric"`
}
