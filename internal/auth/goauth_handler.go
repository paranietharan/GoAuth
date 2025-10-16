// internal/auth/handler.go
package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
)

type Handler struct {
	service  *Service
	validate *validator.Validate
}

func NewHandler(service *Service) *Handler {
	return &Handler{
		service:  service,
		validate: validator.New(),
	}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.Register(&req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondSuccess(w, http.StatusCreated, "User registered successfully. Please check your email to verify your account.", nil)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	response, err := h.service.Login(&req)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, response)
}

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "Token is required")
		return
	}

	if err := h.service.VerifyEmail(token); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondSuccess(w, http.StatusOK, "Email verified successfully", nil)
}

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.ForgotPassword(&req); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to process request")
		return
	}

	respondSuccess(w, http.StatusOK, "If an account exists with this email, a password reset link has been sent", nil)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.ResetPassword(&req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondSuccess(w, http.StatusOK, "Password reset successfully", nil)
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.ChangePassword(userID, &req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondSuccess(w, http.StatusOK, "Password changed successfully", nil)
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.validate.Struct(req); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	response, err := h.service.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, response)
}

func (h *Handler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	respondJSON(w, http.StatusOK, user)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	userIDVal := r.Context().Value("user_id")
	if userIDVal == nil {
		respondError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var userID string
	switch v := userIDVal.(type) {
	case string:
		userID = v
	default:
		respondError(w, http.StatusUnauthorized, "Invalid user ID type")
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.service.Logout(userID, req.RefreshToken); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondSuccess(w, http.StatusOK, "Logged out successfully", nil)
}

func (h *Handler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.service.GetAllUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch users")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Users retrieved successfully",
		"data":    users,
		"count":   len(users),
	})
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userIDVal := r.Context().Value("user_id")
	if userIDVal == nil {
		respondError(w, http.StatusUnauthorized, "User not authenticated")
		return
	}

	var userID string
	switch v := userIDVal.(type) {
	case string:
		userID = v
	default:
		respondError(w, http.StatusUnauthorized, "Invalid user ID type")
		return
	}

	vars := r.Context().Value("vars").(map[string]string)
	var targetUserID string
	_, err := fmt.Sscanf(vars["id"], "%d", &targetUserID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	if userID == targetUserID {
		respondError(w, http.StatusBadRequest, "Cannot delete your own account")
		return
	}

	if err := h.service.Delete(targetUserID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	respondSuccess(w, http.StatusOK, "User deleted successfully", nil)
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, ErrorResponse{Error: message})
}

func respondSuccess(w http.ResponseWriter, status int, message string, data interface{}) {
	respondJSON(w, status, SuccessResponse{Message: message, Data: data})
}
