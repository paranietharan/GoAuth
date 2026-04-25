package dto

type AuthTokensResponse struct {
	AccessToken  string              `json:"access_token"`
	RefreshToken string              `json:"refresh_token"`
	User         UserProfileResponse `json:"user"`
}
