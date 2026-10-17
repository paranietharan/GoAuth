package router

import (
	"log/slog"
	"time"

	apperrors "GoAuth/internal/errors"
	"GoAuth/internal/handler"
	"GoAuth/internal/middleware"
	"GoAuth/internal/model"

	"github.com/gin-gonic/gin"
)

type AuthHandler interface {
	Signup(c *gin.Context)
	Login(c *gin.Context)
	VerifyEmail(c *gin.Context)
	Logout(c *gin.Context)
	LogoutAll(c *gin.Context)
	RefreshSession(c *gin.Context)
	ListSessions(c *gin.Context)
	RevokeSession(c *gin.Context)
	RevokeSessionByID(c *gin.Context)
	ChangePassword(c *gin.Context)
	GetMe(c *gin.Context)
	ForgotPassword(c *gin.Context)
	VerifyForgotPasswordOTP(c *gin.Context)
	PasswordReset(c *gin.Context)
	ListUsers(c *gin.Context)
	UpdateUserStatus(c *gin.Context)
}

type Config struct {
	AuthHandler    AuthHandler
	HealthHandler  *handler.HealthHandler
	AuthMiddleware *middleware.AuthMiddleware
	RateLimiter    *middleware.RateLimiter
	CORSConfig     middleware.CORSConfig
	Logger         *slog.Logger
}

func New(cfg Config) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// Global Middlewares
	r.Use(middleware.RequestID())
	r.Use(middleware.CORS(cfg.CORSConfig))
	r.Use(middleware.Recovery(cfg.Logger))

	// Custom 404 & 405 handlers
	r.NoRoute(func(c *gin.Context) {
		apperrors.Write(c, apperrors.ErrNotFound)
	})
	r.NoMethod(func(c *gin.Context) {
		apperrors.Write(c, apperrors.ErrMethodNotAllowed)
	})

	// Health & Readiness Probes
	if cfg.HealthHandler != nil {
		r.GET("/health", cfg.HealthHandler.Health)
		r.GET("/ready", cfg.HealthHandler.Ready)
	} else {
		r.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})
	}

	// Rate limiter helpers
	loginLimiter := dummyMiddleware()
	registerLimiter := dummyMiddleware()
	otpLimiter := dummyMiddleware()

	if cfg.RateLimiter != nil {
		loginLimiter = cfg.RateLimiter.Limit("login", 10, time.Minute)
		registerLimiter = cfg.RateLimiter.Limit("register", 5, time.Minute)
		otpLimiter = cfg.RateLimiter.Limit("otp", 5, time.Minute)
	}

	api := r.Group("/api/v1")

	// Public Auth Endpoints
	auth := api.Group("/auth")
	{
		auth.POST("/signup", registerLimiter, cfg.AuthHandler.Signup)
		auth.POST("/register", registerLimiter, cfg.AuthHandler.Signup)
		auth.POST("/login", loginLimiter, cfg.AuthHandler.Login)
		auth.POST("/verify-email", otpLimiter, cfg.AuthHandler.VerifyEmail)
		auth.POST("/refresh-session", cfg.AuthHandler.RefreshSession)
		auth.POST("/refresh", cfg.AuthHandler.RefreshSession)
		auth.POST("/forgot-password", otpLimiter, cfg.AuthHandler.ForgotPassword)
		auth.POST("/forgot-password/verify-otp", otpLimiter, cfg.AuthHandler.VerifyForgotPasswordOTP)
		auth.POST("/password-reset", cfg.AuthHandler.PasswordReset)
	}

	// Protected Auth Endpoints
	protectedAuth := auth.Group("")
	protectedAuth.Use(cfg.AuthMiddleware.RequireAuth())
	{
		protectedAuth.POST("/logout", cfg.AuthHandler.Logout)
		protectedAuth.POST("/logout-all", cfg.AuthHandler.LogoutAll)
		protectedAuth.POST("/change-password", cfg.AuthHandler.ChangePassword)
		protectedAuth.GET("/sessions", cfg.AuthHandler.ListSessions)
		protectedAuth.POST("/revoke-session", cfg.AuthHandler.RevokeSession)
		protectedAuth.DELETE("/sessions/:id", cfg.AuthHandler.RevokeSessionByID)
	}

	// Protected User Endpoints
	users := api.Group("/users")
	users.Use(cfg.AuthMiddleware.RequireAuth())
	{
		users.GET("/me", cfg.AuthHandler.GetMe)
	}

	// Admin Endpoints
	admin := api.Group("/admin")
	admin.Use(cfg.AuthMiddleware.RequireAuth(), middleware.RequireRoles(model.RoleAdmin))
	{
		admin.GET("/users", cfg.AuthHandler.ListUsers)
		admin.PATCH("/users/:id/status", cfg.AuthHandler.UpdateUserStatus)
	}

	// RBAC Test & Demonstration Routes
	r.GET("/admin-only", cfg.AuthMiddleware.RequireAuth(), middleware.RequireRoles(model.RoleAdmin), handler.AdminOnly)
	r.GET("/user-admin", cfg.AuthMiddleware.RequireAuth(), middleware.RequireRoles(model.RoleUser, model.RoleAdmin), handler.UserAdmin)
	r.GET("/user-details/:id", cfg.AuthMiddleware.RequireAuth(), handler.UserDetails)
	r.GET("/user-private/:id", cfg.AuthMiddleware.RequireAuth(), handler.UserPrivateDetails)

	return r
}

func dummyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}
