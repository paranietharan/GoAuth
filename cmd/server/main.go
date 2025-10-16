package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"GoAuth/internal/auth"
	"GoAuth/internal/config"
	"GoAuth/internal/database"
	"GoAuth/internal/email"
	"GoAuth/internal/middleware"
	"GoAuth/internal/worker"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

func main() {
	cfg := config.Load()

	db, err := database.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if cfg.RUN_Migrations {
		if err := database.RunMigrations(db, cfg.RUN_Drop_Migrations); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}
	}

	if cfg.SEED_DB {
		if err := database.SeedDatabase(db); err != nil {
			log.Fatalf("Failed to seed database: %v", err)
		}
	}

	emailService := email.NewService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPFrom)

	// Initialize job queue for async operations
	jobQueue := worker.NewJobQueue(100)
	emailWorker := worker.NewEmailWorker(emailService, jobQueue)

	// Start worker pool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emailWorker.Start(ctx, 5) // 5 concurrent workers

	// Initialize repositories
	userRepo := auth.NewUserRepository(db)
	tokenRepo := auth.NewTokenRepository(db)

	// Initialize services
	authService := auth.NewService(userRepo, tokenRepo, emailService, jobQueue, cfg.JWTSecret)

	// Initialize handlers
	authHandler := auth.NewHandler(authService)

	// Setup router
	r := mux.NewRouter()

	// Public routes
	r.HandleFunc("/api/auth/register", authHandler.Register).Methods("POST")
	r.HandleFunc("/api/auth/login", authHandler.Login).Methods("POST")
	r.HandleFunc("/api/auth/verify-email", authHandler.VerifyEmail).Methods("GET")
	r.HandleFunc("/api/auth/forgot-password", authHandler.ForgotPassword).Methods("POST")
	r.HandleFunc("/api/auth/reset-password", authHandler.ResetPassword).Methods("POST")
	r.HandleFunc("/api/auth/refresh", authHandler.RefreshToken).Methods("POST")

	// Protected routes
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(middleware.AuthMiddleware(cfg.JWTSecret))
	protected.HandleFunc("/auth/me", authHandler.GetCurrentUser).Methods("GET")
	protected.HandleFunc("/auth/logout", authHandler.Logout).Methods("POST")
	protected.HandleFunc("/auth/change-password", authHandler.ChangePassword).Methods("POST")

	// Admin-only routes
	admin := r.PathPrefix("/api/admin").Subrouter()
	admin.Use(middleware.AuthMiddleware(cfg.JWTSecret))
	admin.Use(middleware.RoleMiddleware("admin"))
	admin.HandleFunc("/users", authHandler.GetAllUsers).Methods("GET")
	admin.HandleFunc("/users/{id}", authHandler.DeleteUser).Methods("DELETE")

	// Add middleware
	r.Use(middleware.LoggingMiddleware)
	r.Use(middleware.CORSMiddleware)
	r.Use(middleware.RateLimitMiddleware)

	// Setup HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting GoAuth server on port %s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
