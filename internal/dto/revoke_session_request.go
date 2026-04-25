package dto

type RevokeSessionRequest struct {
	SessionID string `json:"session_id" validate:"required,uuid4"`
}
