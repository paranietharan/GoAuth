package email

import (
	"time"
)

// Service coordinates the rendering and sending of emails.
type Service struct {
	provider Provider
	renderer *Renderer
	jobQueue AsyncJobQueue // Interface for async sending
}

type AsyncJobQueue interface {
	Push(job EmailJob)
}

type EmailJob struct {
	To      string
	Subject string
	Body    string
}

func NewService(provider Provider, renderer *Renderer, jobQueue AsyncJobQueue) *Service {
	return &Service{
		provider: provider,
		renderer: renderer,
		jobQueue: jobQueue,
	}
}

func (s *Service) sendAsync(to, subject, templateName string, data map[string]any) error {
	body, err := s.renderer.Render(templateName, data)
	if err != nil {
		return err
	}

	if s.jobQueue != nil {
		s.jobQueue.Push(EmailJob{
			To:      to,
			Subject: subject,
			Body:    body,
		})
		return nil
	}

	// Fallback to synchronous if no queue provided (not recommended for production)
	return s.provider.Send(to, subject, body)
}

func (s *Service) SendSignupEmail(to, otp string, expiryMinutes int) error {
	data := map[string]any{
		"OTP":           otp,
		"ExpiryMinutes": expiryMinutes,
		"Year":          time.Now().Year(),
	}
	return s.sendAsync(to, "Welcome to GoAuth - Verify Your Email", "signup.html", data)
}

func (s *Service) SendVerifyEmail(to string, loginLink string) error {
	data := map[string]any{
		"Email":     to,
		"LoginLink": loginLink,
		"Year":      time.Now().Year(),
	}
	return s.sendAsync(to, "Email Verified Successfully", "verify_email.html", data)
}

func (s *Service) SendLoginNotification(to, ip, device string) error {
	data := map[string]any{
		"Email":      to,
		"IPAddress":  ip,
		"DeviceInfo": device,
		"Timestamp":  time.Now().Format(time.RFC1123),
		"Year":       time.Now().Year(),
	}
	return s.sendAsync(to, "Security Alert: New Login to Your Account", "login.html", data)
}

func (s *Service) SendLogoutNotification(to, reason string) error {
	data := map[string]any{
		"Email":     to,
		"Reason":    reason,
		"Timestamp": time.Now().Format(time.RFC1123),
		"Year":      time.Now().Year(),
	}
	return s.sendAsync(to, "Session Signed Out", "logout.html", data)
}

func (s *Service) SendPasswordResetEmail(to, otp string, expiryMinutes int) error {
	data := map[string]any{
		"OTP":           otp,
		"ExpiryMinutes": expiryMinutes,
		"Year":          time.Now().Year(),
	}
	return s.sendAsync(to, "Reset Your Password", "forgot_password.html", data)
}

func (s *Service) SendPasswordChangedEmail(to, loginLink string) error {
	data := map[string]any{
		"Email":     to,
		"LoginLink": loginLink,
		"Year":      time.Now().Year(),
	}
	return s.sendAsync(to, "Password Changed Successfully", "password_reset_success.html", data)
}
