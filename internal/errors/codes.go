package errors

import "net/http"

var (
	ErrValidationFailed   = New("VALIDATION_FAILED", "validation failed", http.StatusBadRequest)
	ErrUnauthorized       = New("UNAUTHORIZED", "unauthorized", http.StatusUnauthorized)
	ErrForbidden          = New("FORBIDDEN", "forbidden", http.StatusForbidden)
	ErrUserAlreadyExists  = New("USER_ALREADY_EXISTS", "user already exists", http.StatusConflict)
	ErrInvalidCredentials = New("INVALID_CREDENTIALS", "invalid credentials", http.StatusUnauthorized)
	ErrInvalidOTP         = New("INVALID_OTP", "invalid otp", http.StatusBadRequest)
	ErrRefreshExpired     = New("REFRESH_TOKEN_EXPIRED", "refresh token expired", http.StatusUnauthorized)
	ErrNotFound           = New("NOT_FOUND", "resource not found", http.StatusNotFound)
	ErrInternal           = New("INTERNAL_SERVER_ERROR", "internal server error", http.StatusInternalServerError)
	ErrEmailNotVerified   = New("EMAIL_NOT_VERIFIED", "email not verified", http.StatusForbidden)
)
