package dto

type SessionItemResponse struct {
	ID               string `json:"id"`
	AccessExpiresAt  string `json:"access_expires_at"`
	RefreshExpiresAt string `json:"refresh_expires_at"`
	IPAddress        string `json:"ip_address,omitempty"`
	UserAgent        string `json:"user_agent,omitempty"`
	Device           string `json:"device,omitempty"`
	IsRevoked        bool   `json:"is_revoked"`
	CreatedAt        string `json:"created_at"`
}
