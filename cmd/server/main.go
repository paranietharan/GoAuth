package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"GoAuth/internal/config"
	"GoAuth/internal/database"
	"GoAuth/internal/handler"
	"GoAuth/internal/logger"
	"GoAuth/internal/middleware"
	"GoAuth/internal/notification/email"
	"GoAuth/internal/repository"
	"GoAuth/internal/router"
	"GoAuth/internal/service"
	"GoAuth/internal/worker"

	_ "github.com/lib/pq"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	appLogger := logger.New(os.Getenv("ENV") == "production")
	slog.SetDefault(appLogger)

	db, err := database.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		appLogger.Error("Failed to connect to database", slog.Any("error", err))
		os.Exit(1)
	}
	defer db.Close()

	redisClient := database.NewRedisClient(cfg.RedisAddr, cfg.RedisPass, cfg.RedisDB)
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		appLogger.Error("Failed to connect to redis", slog.Any("error", err))
		os.Exit(1)
	}
	defer redisClient.Close()

	var provider email.Provider
	if cfg.IsLocalDevWithoutSMTP {
		provider = &email.MockProvider{}
	} else {
		provider = email.NewSMTPProvider(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPFrom)
	}

	renderer, err := email.NewRenderer("internal/notification/email/templates")
	if err != nil {
		appLogger.Error("Failed to initialize email renderer", slog.Any("error", err))
		os.Exit(1)
	}

	jobQueue := worker.NewJobQueue(100)
	emailSender := email.NewService(provider, renderer, jobQueue)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var workerWg sync.WaitGroup
	emailWorker := worker.NewEmailWorker(provider, jobQueue)
	emailWorker.Start(ctx, 5, &workerWg)

	userRepo := repository.NewPostgresUserRepository(db)
	sessionRepo := repository.NewPostgresSessionRepository(db)
	otpRepo := repository.NewRedisOTPRepository(redisClient)

	authService := service.NewAuthService(
		userRepo,
		sessionRepo,
		otpRepo,
		emailSender,
		service.AuthConfig{
			JWTSecret:            cfg.JWTSecret,
			BcryptCost:           cfg.BcryptCost,
			AccessTokenTTL:       time.Duration(cfg.AccessTokenTTLMinutes) * time.Minute,
			RefreshTokenTTL:      time.Duration(cfg.RefreshTokenTTLDays) * 24 * time.Hour,
			EmailVerificationTTL: cfg.EmailVerificationTTL,
			ForgotPasswordOTPTTL: cfg.ForgotPasswordOTPTTL,
			ResetTempTokenTTL:    cfg.ResetTempTokenTTL,
		},
		appLogger,
	)

	authMiddleware := middleware.NewAuthMiddleware(cfg.JWTSecret, sessionRepo, userRepo)
	authHandler := handler.NewAuthHandler(authService)
	healthHandler := handler.NewHealthHandler(db, redisClient)
	rateLimiter := middleware.NewRateLimiter(redisClient)

	engine := router.New(router.Config{
		AuthHandler:    authHandler,
		HealthHandler:  healthHandler,
		AuthMiddleware: authMiddleware,
		RateLimiter:    rateLimiter,
		CORSConfig:     middleware.DefaultCORSConfig(cfg.CORSAllowedOrigins),
		Logger:         appLogger,
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      engine,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		appLogger.Info("Starting GoAuth server", slog.String("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("Server listen failed", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		appLogger.Error("Server forced to shutdown", slog.Any("error", err))
	}

	cancel()
	workerWg.Wait()

	appLogger.Info("Server exited cleanly")
}
