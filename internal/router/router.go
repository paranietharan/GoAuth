package router

import (
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
	RefreshSession(c *gin.Context)
	ListSessions(c *gin.Context)
	RevokeSession(c *gin.Context)
	ForgotPassword(c *gin.Context)
	VerifyForgotPasswordOTP(c *gin.Context)
	PasswordReset(c *gin.Context)
}

func New(authHandler AuthHandler, authMiddleware *middleware.AuthMiddleware) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	api := r.Group("/api/v1")
	auth := api.Group("/auth")
	{
		auth.POST("/signup", authHandler.Signup)
		auth.POST("/login", authHandler.Login)
		auth.POST("/verify-email", authHandler.VerifyEmail)
		auth.POST("/refresh-session", authHandler.RefreshSession)
		auth.POST("/forgot-password", authHandler.ForgotPassword)
		auth.POST("/forgot-password/verify-otp", authHandler.VerifyForgotPasswordOTP)
		auth.POST("/password-reset", authHandler.PasswordReset)
	}

	protected := auth.Group("")
	protected.Use(authMiddleware.RequireAuth())
	{
		protected.POST("/logout", authHandler.Logout)
		protected.GET("/sessions", authHandler.ListSessions)
		protected.POST("/revoke-session", authHandler.RevokeSession)
	}

	// 1. Admin Only
	r.GET("/admin-only", authMiddleware.RequireAuth(), middleware.RequireRoles(model.RoleAdmin), handler.AdminOnly)
	// 2. User and Admin (Both can access)
	r.GET("/user-admin", authMiddleware.RequireAuth(), middleware.RequireRoles(model.RoleUser, model.RoleAdmin), handler.UserAdmin)
	// 3. Particular User and Admin (Ownership + Admin Override)
	r.GET("/user-details/:id", authMiddleware.RequireAuth(), handler.UserDetails)
	// 4. Particular User Only (Strict Ownership - No Admin)
	r.GET("/user-private/:id", authMiddleware.RequireAuth(), handler.UserPrivateDetails)

	return r
}
