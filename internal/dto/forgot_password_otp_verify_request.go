package dto

type ForgotPasswordOTPVerifyRequest struct {
	Email string `json:"email" validate:"required,email,max=320"`
	OTP   string `json:"otp" validate:"required,len=6,numeric"`
}
