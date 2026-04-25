package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"GoAuth/internal/config"
	"GoAuth/internal/database"
	"GoAuth/internal/handler"
	"GoAuth/internal/middleware"
	"GoAuth/internal/notification/email"
	"GoAuth/internal/repository"
	"GoAuth/internal/router"
	"GoAuth/internal/service"
	"GoAuth/internal/worker"

	_ "github.com/lib/pq"
)

type appLogger struct{}

func (l *appLogger) InfoContext(ctx context.Context, msg string, args ...any)  { log.Printf("INFO: "+msg, args...) }
func (l *appLogger) WarnContext(ctx context.Context, msg string, args ...any)  { log.Printf("WARN: "+msg, args...) }
func (l *appLogger) ErrorContext(ctx context.Context, msg string, args ...any) { log.Printf("ERROR: "+msg, args...) }

func main() {
	cfg := config.Load()

	// 1. Database & Redis
	db, err := database.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	redisClient := database.NewRedisClient(cfg.RedisAddr, cfg.RedisPass, cfg.RedisDB)
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to redis: %v", err)
	}

	// 2. Email System Initialization
	var provider email.Provider
	if cfg.IsLocalDevWithoutSMTP {
		provider = &email.MockProvider{}
	} else {
		provider = email.NewSMTPProvider(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPFrom)
	}

	renderer, err := email.NewRenderer("internal/notification/email/templates")
	if err != nil {
		log.Fatalf("Failed to initialize email renderer: %v", err)
	}

	jobQueue := worker.NewJobQueue(100)
	emailSender := email.NewService(provider, renderer, jobQueue)

	// 3. Worker Pool Initialization
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	emailWorker := worker.NewEmailWorker(provider, jobQueue)
	emailWorker.Start(ctx, 5)

	// 4. Repositories
	userRepo := repository.NewPostgresUserRepository(db)
	sessionRepo := repository.NewPostgresSessionRepository(db)
	otpRepo := repository.NewRedisOTPRepository(redisClient)

	// 5. Services
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
		&appLogger{},
	)

	// 6. Middleware & Handlers
	authMiddleware := middleware.NewAuthMiddleware(cfg.JWTSecret, sessionRepo)
	authHandler := handler.NewAuthHandler(authService)

	// 7. Router
	engine := router.New(authHandler, authMiddleware)

	// 8. Server setup
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      engine,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Starting GoAuth server on port %s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server exited")
}
