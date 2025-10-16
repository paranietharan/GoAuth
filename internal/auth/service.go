package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"GoAuth/internal/email"
	"GoAuth/internal/worker"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	userRepo     *UserRepository
	tokenRepo    *TokenRepository
	emailService *email.Service
	jobQueue     *worker.JobQueue
	jwtSecret    string
}

func NewService(userRepo *UserRepository, tokenRepo *TokenRepository, emailService *email.Service, jobQueue *worker.JobQueue, jwtSecret string) *Service {
	return &Service{
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		emailService: emailService,
		jobQueue:     jobQueue,
		jwtSecret:    jwtSecret,
	}
}

func (s *Service) Register(req *RegisterRequest) error {
	existingUser, _ := s.userRepo.GetByEmail(req.Email)
	if existingUser != nil {
		return fmt.Errorf("user with this email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	userRole, err := s.userRepo.GetRole("user")
	if err != nil {
		return fmt.Errorf("failed to get user role: %w", err)
	}

	user := &User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		RoleID:       &userRole.ID,
	}

	if err := s.userRepo.Create(user); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	verificationToken, err := s.generateToken()
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	token := &Token{
		UserID:    user.ID,
		Token:     verificationToken,
		TokenType: "email_verification",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.tokenRepo.Create(token); err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	job := &worker.EmailJob{
		To:      user.Email,
		Subject: "Verify Your Email",
		Body:    fmt.Sprintf("Click here to verify: http://localhost:8080/api/auth/verify-email?token=%s", verificationToken),
	}
	s.jobQueue.Push(job)

	return nil
}

func (s *Service) Login(req *LoginRequest) (*LoginResponse, error) {
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !user.IsActive {
		return nil, fmt.Errorf("account is deactivated")
	}

	accessToken, err := s.generateJWT(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	rt := &RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	if err := s.tokenRepo.CreateRefreshToken(rt); err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

func (s *Service) VerifyEmail(tokenStr string) error {
	token, err := s.tokenRepo.GetByToken(tokenStr)
	if err != nil {
		return fmt.Errorf("invalid token")
	}

	if token.IsUsed {
		return fmt.Errorf("token already used")
	}

	if time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("token expired")
	}

	if token.TokenType != "email_verification" {
		return fmt.Errorf("invalid token type")
	}

	if err := s.userRepo.UpdateVerified(token.UserID, true); err != nil {
		return fmt.Errorf("failed to verify user: %w", err)
	}

	if err := s.tokenRepo.MarkAsUsed(token.ID); err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	return nil
}

func (s *Service) ForgotPassword(req *ForgotPasswordRequest) error {
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil
	}

	resetToken, err := s.generateToken()
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	token := &Token{
		UserID:    user.ID,
		Token:     resetToken,
		TokenType: "password_reset",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	if err := s.tokenRepo.Create(token); err != nil {
		return fmt.Errorf("failed to create reset token: %w", err)
	}

	job := &worker.EmailJob{
		To:      user.Email,
		Subject: "Reset Your Password",
		Body:    fmt.Sprintf("Click here to reset: http://localhost:8080/reset?token=%s", resetToken),
	}
	s.jobQueue.Push(job)

	return nil
}

func (s *Service) ResetPassword(req *ResetPasswordRequest) error {
	token, err := s.tokenRepo.GetByToken(req.Token)
	if err != nil {
		return fmt.Errorf("invalid token")
	}

	if token.IsUsed {
		return fmt.Errorf("token already used")
	}

	if time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("token expired")
	}

	if token.TokenType != "password_reset" {
		return fmt.Errorf("invalid token type")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(token.UserID, string(hashedPassword)); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark token as used
	if err := s.tokenRepo.MarkAsUsed(token.ID); err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	return nil
}

func (s *Service) ChangePassword(userID string, req *ChangePasswordRequest) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		return fmt.Errorf("invalid old password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(userID, string(hashedPassword)); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

func (s *Service) RefreshAccessToken(refreshTokenStr string) (*LoginResponse, error) {
	rt, err := s.tokenRepo.GetRefreshToken(refreshTokenStr)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if rt.IsRevoked {
		return nil, fmt.Errorf("refresh token revoked")
	}

	if time.Now().After(rt.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}

	user, err := s.userRepo.GetByID(rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate new access token
	accessToken, err := s.generateJWT(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenStr,
		User:         user,
	}, nil
}

func (s *Service) Logout(userID string, refreshToken string) error {
	rt, err := s.tokenRepo.GetRefreshToken(refreshToken)
	if err != nil {
		return nil // Silent fail
	}

	if rt.UserID != userID {
		return fmt.Errorf("unauthorized")
	}

	return s.tokenRepo.RevokeRefreshToken(rt.ID)
}

func (s *Service) generateJWT(user *User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *Service) generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *Service) GetAllUsers() ([]User, error) {
	users, err := s.userRepo.GetAll()
	if err != nil {
		log.Printf("Error fetching all users : %v\n", err)
		return nil, fmt.Errorf("failed to get all users: %w", err)
	}
	return users, nil
}

func (s *Service) Delete(userID string) error {
	_, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if err := s.userRepo.Delete(userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if err := s.tokenRepo.RevokeAllUserRefreshTokens(userID); err != nil {
		fmt.Printf("Warning: failed to clean up tokens for user %s: %v\n", userID, err)
	}

	return nil
}

func (s *Service) GetByUserID(userID string) (*User, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return &User{}, fmt.Errorf("user not found")
	}
	return user, nil
}
