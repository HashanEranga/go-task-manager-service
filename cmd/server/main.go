package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/repository"
	"github.com/HashanEranga/go-task-manager-service/internal/services"
	"github.com/HashanEranga/go-task-manager-service/pkg/jwt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/HashanEranga/go-task-manager-service/internal/config"
	"github.com/HashanEranga/go-task-manager-service/internal/database"
	"github.com/HashanEranga/go-task-manager-service/internal/handlers"
	appmiddleware "github.com/HashanEranga/go-task-manager-service/internal/middleware"
	"github.com/HashanEranga/go-task-manager-service/pkg/logger"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	logger.Init(cfg.App.LogLevel)
	logger.Info("Starting TaskFlow server...")

	db, err := database.NewGormDatabase(cfg)
	if err != nil {
		logger.Error("Failed to create database", err)
		os.Exit(1)
	}

	if err := db.Connect(); err != nil {
		logger.Error("Failed to connect to database", err)
		os.Exit(1)
	}
	defer func(db database.Database) {
		err := db.Close()
		if err != nil {
			logger.Error("Failed to close database connection", err)
		}
	}(db)

	logger.Info(fmt.Sprintf("Connected to %s database successfully", db.GetDriverName()))

	gormDB := db.GetGormDB()
	tokenManager := jwt.NewTokenManager(
		cfg.JWT.Secret,
		cfg.JWT.Expiry,
		cfg.JWT.RefreshExpiry,
	)

	userRepo := repository.NewUserRepository(gormDB)
	authRepo := repository.NewAuthRepository(gormDB)
	roleRepo := repository.NewRoleRepository(gormDB)
	auditRepo := repository.NewAuditRepository(gormDB)

	authService := services.NewAuthService(userRepo, authRepo, roleRepo, auditRepo, tokenManager)
	userService := services.NewUserService(userRepo, roleRepo)

	authHandler := handlers.NewAuthHandler(authService)
	userHandler := handlers.NewUserHandler(userService)

	authMiddleware := appmiddleware.NewAuthMiddleware(tokenManager)

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:*", "https://localhost:*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	healthHandler := handlers.NewHealthHandler(db)

	r.Get("/health", healthHandler.Health)
	r.Get("/health/db", healthHandler.HealthDB)

	r.Route("/api", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("TaskFlow API v1.0 with GORM"))
		})

		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", authHandler.Register)
			r.Post("/login", authHandler.Login)
			r.Post("/refresh", authHandler.RefreshToken)

			r.Group(func(r chi.Router) {
				r.Use(authMiddleware.Authenticate)
				r.Get("/me", authHandler.Me)
				r.Post("/logout", authHandler.Logout)
			})
		})

		// User Management Routes (Admin only)
		r.Route("/users", func(r chi.Router) {
			// All user management requires authentication AND users.manage permission
			r.Use(authMiddleware.Authenticate)
			r.Use(authMiddleware.RequirePermission("users.manage"))

			r.Get("/", userHandler.ListUsers)
			r.Get("/{id}", userHandler.GetUser)
			r.Post("/", userHandler.CreateUser)
			r.Put("/{id}", userHandler.UpdateUser)
			r.Delete("/{id}", userHandler.DeleteUser)

			// User status management
			r.Patch("/{id}/activate", userHandler.ActivateUser)
			r.Patch("/{id}/deactivate", userHandler.DeactivateUser)

			// Role management
			r.Post("/{id}/roles", userHandler.AssignRole)
			r.Delete("/{id}/roles/{roleId}", userHandler.RevokeRole)
		})
	})

	serverAddr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		logger.Info(fmt.Sprintf("Server starting on %s", serverAddr))
		logger.Info(fmt.Sprintf("Using database: %s", cfg.Database.Driver))
		logger.Info(fmt.Sprintf("Environment: %s", cfg.App.Environment))

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Server failed to start", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", err)
	}

	logger.Info("Server stopped")
}
