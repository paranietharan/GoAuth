package service

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"GoAuth/internal/dto"
	apperrors "GoAuth/internal/errors"
	"GoAuth/internal/model"
	"GoAuth/internal/repository"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	otpRepo repository.OTPRepository,
	emailSender EmailSender,
	cfg AuthConfig,
	logger Logger,
) *AuthService {
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = 12
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if cfg.EmailVerificationTTL == 0 {
		cfg.EmailVerificationTTL = 10 * time.Minute
	}
	if cfg.ForgotPasswordOTPTTL == 0 {
		cfg.ForgotPasswordOTPTTL = 10 * time.Minute
	}
	if cfg.ResetTempTokenTTL == 0 {
		cfg.ResetTempTokenTTL = 15 * time.Minute
	}

	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		otpRepo:     otpRepo,
		emailSender: emailSender,
		cfg:         cfg,
		logger:      logger,
	}
}

func (s *AuthService) Signup(ctx context.Context, req dto.SignupRequest) *apperrors.AppError {
	normalizedEmail := normalizeEmail(req.Email)

	exists, err := s.userRepo.IsEmailTaken(ctx, normalizedEmail)
	if err != nil {
		s.logger.ErrorContext(ctx, "signup email check failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if exists {
		return apperrors.ErrUserAlreadyExists
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), s.cfg.BcryptCost)
	if err != nil {
		s.logger.ErrorContext(ctx, "signup password hash failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	now := nowUTC()
	user := &model.User{
		ID:              uuid.New(),
		Email:           normalizedEmail,
		PasswordHash:    string(passwordHash),
		Role:            model.RoleUser,
		IsActive:        true,
		IsEmailVerified: false,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.ErrorContext(ctx, "signup user create failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	otp, err := randomOTP6()
	if err != nil {
		s.logger.ErrorContext(ctx, "signup otp generation failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if err := s.otpRepo.SetEmailVerificationOTP(ctx, normalizedEmail, otp, s.cfg.EmailVerificationTTL); err != nil {
		s.logger.ErrorContext(ctx, "signup redis otp save failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	expiryMinutes := int(s.cfg.EmailVerificationTTL.Minutes())
	if err := s.emailSender.SendSignupEmail(user.Email, otp, expiryMinutes); err != nil {
		s.logger.ErrorContext(ctx, "failed to send signup email", "error", err, "email", user.Email)
	}

	s.logger.InfoContext(ctx, "signup success", "email", normalizedEmail)
	return nil
}

func (s *AuthService) Login(ctx context.Context, req dto.LoginRequest, meta RequestMeta) (*dto.AuthTokensResponse, *apperrors.AppError) {
	normalizedEmail := normalizeEmail(req.Email)
	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, apperrors.ErrInvalidCredentials
		}
		s.logger.ErrorContext(ctx, "login user lookup failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		return nil, apperrors.ErrInvalidCredentials
	}
	if !user.IsActive {
		return nil, apperrors.ErrForbidden
	}
	if !user.IsEmailVerified {
		return nil, apperrors.ErrEmailNotVerified
	}

	now := nowUTC()
	sessionID := uuid.New()
	accessToken, accessExp, err := s.issueAccessToken(user.ID.String(), sessionID.String(), user.Role, now)
	if err != nil {
		s.logger.ErrorContext(ctx, "login access token issue failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	refreshToken, err := randomToken(48)
	if err != nil {
		s.logger.ErrorContext(ctx, "login refresh token issue failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	ip := strings.TrimSpace(meta.IPAddress)
	ua := strings.TrimSpace(meta.UserAgent)
	device := strings.TrimSpace(meta.Device)

	session := &model.Session{
		ID:               sessionID,
		UserID:           user.ID,
		AccessTokenHash:  hashToken(accessToken),
		RefreshTokenHash: hashToken(refreshToken),
		AccessExpiresAt:  accessExp,
		RefreshExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
		IsRevoked:        false,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if ip != "" {
		session.IPAddress = &ip
	}
	if ua != "" {
		session.UserAgent = &ua
	}
	if device != "" {
		session.Device = &device
	}

	if err := s.sessionRepo.CreateWithLoginMetadata(ctx, session, repository.LoginMetadata{
		UserID:    user.ID,
		At:        now,
		IPAddress: ip,
		UserAgent: ua,
		Device:    device,
	}); err != nil {
		s.logger.ErrorContext(ctx, "login session persist failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	if err := s.emailSender.SendLoginNotification(user.Email, meta.IPAddress, meta.Device); err != nil {
		s.logger.ErrorContext(ctx, "failed to send login notification", "error", err, "email", user.Email)
	}

	return &dto.AuthTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: dto.UserProfileResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			Role:            string(user.Role),
			IsActive:        user.IsActive,
			IsEmailVerified: user.IsEmailVerified,
		},
	}, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, req dto.VerifyEmailRequest) *apperrors.AppError {
	normalizedEmail := normalizeEmail(req.Email)
	storedOTP, found, err := s.otpRepo.GetEmailVerificationOTP(ctx, normalizedEmail)
	if err != nil {
		s.logger.ErrorContext(ctx, "verify email redis read failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if !found || !safeStringEqual(storedOTP, req.OTP) {
		return apperrors.ErrInvalidOTP
	}

	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			return apperrors.ErrNotFound
		}
		s.logger.ErrorContext(ctx, "verify email user lookup failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if err := s.userRepo.MarkEmailVerified(ctx, user.ID, nowUTC()); err != nil {
		s.logger.ErrorContext(ctx, "verify email update failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if err := s.otpRepo.DeleteEmailVerificationOTP(ctx, normalizedEmail); err != nil {
		s.logger.WarnContext(ctx, "verify email otp delete failed", "error", err)
	}

	if err := s.emailSender.SendVerifyEmail(user.Email, "/login"); err != nil {
		s.logger.WarnContext(ctx, "failed to send verification success email", "error", err, "email", user.Email)
	}

	return nil
}

func (s *AuthService) Logout(ctx context.Context, principal AuthPrincipal, refreshToken string) *apperrors.AppError {
	sessionID, err := uuid.Parse(principal.SessionID)
	if err != nil {
		return apperrors.ErrUnauthorized
	}
	if err := s.sessionRepo.RevokeByID(ctx, sessionID); err != nil {
		s.logger.ErrorContext(ctx, "logout revoke by session id failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	if strings.TrimSpace(refreshToken) != "" {
		session, err := s.sessionRepo.GetByRefreshTokenHash(ctx, hashToken(refreshToken))
		if err == nil {
			_ = s.sessionRepo.RevokeByID(ctx, session.ID)
		}
	}

	if err := s.emailSender.SendLogoutNotification(principal.UserID, "Session Revoked"); err != nil {
		s.logger.ErrorContext(ctx, "failed to send revocation notification", "error", err, "email", principal.UserID)
	}
	return nil
}

func (s *AuthService) RefreshSession(ctx context.Context, refreshToken string, meta RequestMeta) (*dto.AuthTokensResponse, *apperrors.AppError) {
	refreshHash := hashToken(refreshToken)
	session, err := s.sessionRepo.GetByRefreshTokenHash(ctx, refreshHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, apperrors.ErrUnauthorized
		}
		s.logger.ErrorContext(ctx, "refresh session lookup failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	now := nowUTC()
	if session.IsRevoked {
		return nil, apperrors.ErrUnauthorized
	}
	if session.RefreshExpired(now) {
		return nil, apperrors.ErrRefreshExpired
	}

	user, err := s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, apperrors.ErrUnauthorized
		}
		s.logger.ErrorContext(ctx, "refresh user lookup failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if !user.IsActive {
		return nil, apperrors.ErrForbidden
	}

	if err := s.sessionRepo.RevokeByID(ctx, session.ID); err != nil {
		s.logger.ErrorContext(ctx, "refresh rotate old revoke failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	newSessionID := uuid.New()
	accessToken, accessExp, err := s.issueAccessToken(user.ID.String(), newSessionID.String(), user.Role, now)
	if err != nil {
		s.logger.ErrorContext(ctx, "refresh issue access failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	newRefreshToken, err := randomToken(48)
	if err != nil {
		s.logger.ErrorContext(ctx, "refresh issue token failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	ip := strings.TrimSpace(meta.IPAddress)
	ua := strings.TrimSpace(meta.UserAgent)
	device := strings.TrimSpace(meta.Device)
	newSession := &model.Session{
		ID:               newSessionID,
		UserID:           user.ID,
		AccessTokenHash:  hashToken(accessToken),
		RefreshTokenHash: hashToken(newRefreshToken),
		AccessExpiresAt:  accessExp,
		RefreshExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
		IsRevoked:        false,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if ip != "" {
		newSession.IPAddress = &ip
	}
	if ua != "" {
		newSession.UserAgent = &ua
	}
	if device != "" {
		newSession.Device = &device
	}
	if err := s.sessionRepo.Create(ctx, newSession); err != nil {
		s.logger.ErrorContext(ctx, "refresh new session create failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	return &dto.AuthTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		User: dto.UserProfileResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			Role:            string(user.Role),
			IsActive:        user.IsActive,
			IsEmailVerified: user.IsEmailVerified,
		},
	}, nil
}

func (s *AuthService) ListSessions(ctx context.Context, principal AuthPrincipal) (*dto.SessionsResponse, *apperrors.AppError) {
	userID, err := uuid.Parse(principal.UserID)
	if err != nil {
		return nil, apperrors.ErrUnauthorized
	}
	sessions, err := s.sessionRepo.ListActiveByUserID(ctx, userID)
	if err != nil {
		s.logger.ErrorContext(ctx, "list sessions failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	items := make([]dto.SessionItemResponse, 0, len(sessions))
	for _, session := range sessions {
		item := dto.SessionItemResponse{
			ID:               session.ID.String(),
			AccessExpiresAt:  session.AccessExpiresAt.Format(time.RFC3339),
			RefreshExpiresAt: session.RefreshExpiresAt.Format(time.RFC3339),
			IsRevoked:        session.IsRevoked,
			CreatedAt:        session.CreatedAt.Format(time.RFC3339),
		}
		if session.IPAddress != nil {
			item.IPAddress = *session.IPAddress
		}
		if session.UserAgent != nil {
			item.UserAgent = *session.UserAgent
		}
		if session.Device != nil {
			item.Device = *session.Device
		}
		items = append(items, item)
	}
	return &dto.SessionsResponse{Sessions: items}, nil
}

func (s *AuthService) RevokeSession(ctx context.Context, principal AuthPrincipal, targetSessionID string) *apperrors.AppError {
	userID, err := uuid.Parse(principal.UserID)
	if err != nil {
		return apperrors.ErrUnauthorized
	}
	sessionID, err := uuid.Parse(targetSessionID)
	if err != nil {
		return apperrors.ErrValidationFailed
	}

	revoked, err := s.sessionRepo.RevokeByIDForUser(ctx, sessionID, userID)
	if err != nil {
		s.logger.ErrorContext(ctx, "revoke session failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if !revoked {
		return apperrors.ErrNotFound
	}
	return nil
}

func (s *AuthService) ForgotPassword(ctx context.Context, req dto.ForgotPasswordRequest) *apperrors.AppError {
	normalizedEmail := normalizeEmail(req.Email)
	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		s.logger.ErrorContext(ctx, "forgot password user lookup failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	otp, err := randomOTP6()
	if err != nil {
		s.logger.ErrorContext(ctx, "forgot password otp generation failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if err := s.otpRepo.SetForgotPasswordOTP(ctx, normalizedEmail, otp, s.cfg.ForgotPasswordOTPTTL); err != nil {
		s.logger.ErrorContext(ctx, "forgot password redis otp save failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	expiryMinutes := int(s.cfg.ForgotPasswordOTPTTL.Minutes())
	if err := s.emailSender.SendPasswordResetEmail(user.Email, otp, expiryMinutes); err != nil {
		s.logger.ErrorContext(ctx, "failed to send password reset email", "error", err, "email", user.Email)
	}
	return nil
}

func (s *AuthService) VerifyForgotPasswordOTP(ctx context.Context, req dto.ForgotPasswordOTPVerifyRequest) (*dto.ForgotPasswordOTPVerifyResponse, *apperrors.AppError) {
	normalizedEmail := normalizeEmail(req.Email)
	storedOTP, found, err := s.otpRepo.GetForgotPasswordOTP(ctx, normalizedEmail)
	if err != nil {
		s.logger.ErrorContext(ctx, "forgot otp redis read failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if !found || !safeStringEqual(storedOTP, req.OTP) {
		return nil, apperrors.ErrInvalidOTP
	}

	tempToken, err := randomToken(48)
	if err != nil {
		s.logger.ErrorContext(ctx, "temp token generation failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	tempTokenHash := hashToken(tempToken)
	if err := s.otpRepo.SetPasswordResetTempToken(ctx, tempTokenHash, normalizedEmail, s.cfg.ResetTempTokenTTL); err != nil {
		s.logger.ErrorContext(ctx, "temp token redis save failed", "error", err)
		return nil, apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if err := s.otpRepo.DeleteForgotPasswordOTP(ctx, normalizedEmail); err != nil {
		s.logger.WarnContext(ctx, "forgot otp cleanup failed", "error", err)
	}
	return &dto.ForgotPasswordOTPVerifyResponse{TempToken: tempToken}, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, req dto.PasswordResetRequest) *apperrors.AppError {
	normalizedEmail := normalizeEmail(req.Email)
	tokenHash := hashToken(req.TempToken)

	storedEmail, found, err := s.otpRepo.GetPasswordResetTempTokenEmail(ctx, tokenHash)
	if err != nil {
		s.logger.ErrorContext(ctx, "reset password temp token lookup failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if !found {
		return apperrors.ErrUnauthorized
	}
	if !safeStringEqual(storedEmail, normalizedEmail) {
		return apperrors.ErrUnauthorized
	}

	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			return apperrors.ErrNotFound
		}
		s.logger.ErrorContext(ctx, "reset password user lookup failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), s.cfg.BcryptCost)
	if err != nil {
		s.logger.ErrorContext(ctx, "reset password hash failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if err := s.userRepo.UpdatePasswordHash(ctx, user.ID, string(passwordHash)); err != nil {
		s.logger.ErrorContext(ctx, "reset password update failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if err := s.sessionRepo.RevokeAllByUserID(ctx, user.ID); err != nil {
		s.logger.ErrorContext(ctx, "reset password revoke sessions failed", "error", err)
		return apperrors.Wrap(apperrors.ErrInternal.Code, apperrors.ErrInternal.Message, apperrors.ErrInternal.HTTPStatus, err)
	}
	if err := s.otpRepo.DeletePasswordResetTempToken(ctx, tokenHash); err != nil {
		s.logger.WarnContext(ctx, "reset password temp token delete failed", "error", err)
	}

	if err := s.emailSender.SendPasswordChangedEmail(user.Email, "/login"); err != nil {
		s.logger.WarnContext(ctx, "reset password notification failed", "error", err)
	}
	return nil
}
