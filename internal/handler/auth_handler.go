package handler

import (
	"strings"

	"GoAuth/internal/dto"
	apperrors "GoAuth/internal/errors"
	"GoAuth/internal/model"
	"GoAuth/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type AuthHandler struct {
	authService *service.AuthService
	validate    *validator.Validate
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService, validate: validator.New(validator.WithRequiredStructEnabled())}
}

func (h *AuthHandler) Signup(c *gin.Context) {
	var req dto.SignupRequest
	if appErr := h.bindAndValidate(c, &req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}

	if appErr := h.authService.Signup(c.Request.Context(), req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, dto.MessageResponse{Message: "signup successful, please verify email"})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if appErr := h.bindAndValidate(c, &req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	resp, appErr := h.authService.Login(c.Request.Context(), req, requestMeta(c))
	if appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, resp)
}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req dto.VerifyEmailRequest
	if appErr := h.bindAndValidate(c, &req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	if appErr := h.authService.VerifyEmail(c.Request.Context(), req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, dto.MessageResponse{Message: "email verified"})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req = dto.LogoutRequest{}
	}
	principal, appErr := principalFromContext(c)
	if appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	if appErr := h.authService.Logout(c.Request.Context(), principal, req.RefreshToken); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, dto.MessageResponse{Message: "logout successful"})
}

func (h *AuthHandler) RefreshSession(c *gin.Context) {
	var req dto.RefreshSessionRequest
	if appErr := h.bindAndValidate(c, &req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	resp, appErr := h.authService.RefreshSession(c.Request.Context(), req.RefreshToken, requestMeta(c))
	if appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, resp)
}

func (h *AuthHandler) ListSessions(c *gin.Context) {
	principal, appErr := principalFromContext(c)
	if appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	resp, appErr := h.authService.ListSessions(c.Request.Context(), principal)
	if appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, resp)
}

func (h *AuthHandler) RevokeSession(c *gin.Context) {
	principal, appErr := principalFromContext(c)
	if appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	var req dto.RevokeSessionRequest
	if appErr := h.bindAndValidate(c, &req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	if appErr := h.authService.RevokeSession(c.Request.Context(), principal, req.SessionID); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, dto.MessageResponse{Message: "session revoked"})
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req dto.ForgotPasswordRequest
	if appErr := h.bindAndValidate(c, &req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	if appErr := h.authService.ForgotPassword(c.Request.Context(), req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, dto.MessageResponse{Message: "if account exists, otp sent"})
}

func (h *AuthHandler) VerifyForgotPasswordOTP(c *gin.Context) {
	var req dto.ForgotPasswordOTPVerifyRequest
	if appErr := h.bindAndValidate(c, &req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	resp, appErr := h.authService.VerifyForgotPasswordOTP(c.Request.Context(), req)
	if appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, resp)
}

func (h *AuthHandler) PasswordReset(c *gin.Context) {
	var req dto.PasswordResetRequest
	if appErr := h.bindAndValidate(c, &req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	if appErr := h.authService.ResetPassword(c.Request.Context(), req); appErr != nil {
		apperrors.Write(c, appErr)
		return
	}
	c.JSON(200, dto.MessageResponse{Message: "password reset successful"})
}

func (h *AuthHandler) bindAndValidate(c *gin.Context, req any) *apperrors.AppError {
	if err := c.ShouldBindJSON(req); err != nil {
		return apperrors.Wrap(apperrors.ErrValidationFailed.Code, apperrors.ErrValidationFailed.Message, apperrors.ErrValidationFailed.HTTPStatus, err)
	}
	if err := h.validate.Struct(req); err != nil {
		return apperrors.Wrap(apperrors.ErrValidationFailed.Code, apperrors.ErrValidationFailed.Message, apperrors.ErrValidationFailed.HTTPStatus, err)
	}
	return nil
}

func requestMeta(c *gin.Context) service.RequestMeta {
	userAgent := strings.TrimSpace(c.Request.UserAgent())
	return service.RequestMeta{
		IPAddress: strings.TrimSpace(c.ClientIP()),
		UserAgent: userAgent,
		Device:    deriveDevice(userAgent),
	}
}

func principalFromContext(c *gin.Context) (service.AuthPrincipal, *apperrors.AppError) {
	userID, ok := c.Get("user_id")
	if !ok {
		return service.AuthPrincipal{}, apperrors.ErrUnauthorized
	}
	role, ok := c.Get("role")
	if !ok {
		return service.AuthPrincipal{}, apperrors.ErrUnauthorized
	}
	sessionID, ok := c.Get("session_id")
	if !ok {
		return service.AuthPrincipal{}, apperrors.ErrUnauthorized
	}

	uid, ok1 := userID.(string)
	r, ok2 := role.(string)
	sid, ok3 := sessionID.(string)
	if !ok1 || !ok2 || !ok3 {
		return service.AuthPrincipal{}, apperrors.ErrUnauthorized
	}

	modelRole := model.Role(r)
	if !modelRole.IsValid() {
		return service.AuthPrincipal{}, apperrors.ErrUnauthorized
	}

	return service.AuthPrincipal{UserID: uid, Role: modelRole, SessionID: sid}, nil
}

func deriveDevice(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "iphone"):
		return "iPhone"
	case strings.Contains(ua, "ipad"):
		return "iPad"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		return "macOS"
	case strings.Contains(ua, "linux"):
		return "Linux"
	default:
		return "Unknown Device"
	}
}
