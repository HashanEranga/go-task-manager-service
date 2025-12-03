# Go Application Setup Guide

Complete guide to setting up the TaskFlow Go application with dual database support (PostgreSQL and SQL Server).

## 📋 Table of Contents

1. [Project Initialization](#project-initialization)
2. [Project Structure](#project-structure)
3. [Configuration System](#configuration-system)
4. [Database Connection](#database-connection)
5. [Running the Server](#running-the-server)
6. [Testing Database Connection](#testing-database-connection)

---

## Project Initialization

### Step 1: Initialize Go Module

```powershell
# Make sure you're in the project directory
cd C:\Users\HashanEranga\Documents\projects\goApps\go-task-manager-service

# Initialize Go module
go mod init github.com/yourusername/go-task-manager-service

# Install required dependencies
go get github.com/go-chi/chi/v5
go get github.com/go-chi/cors
go get github.com/lib/pq
go get github.com/denisenkom/go-mssqldb
go get github.com/spf13/viper
go get github.com/rs/zerolog
go get github.com/joho/godotenv
go get golang.org/x/crypto/bcrypt
go get github.com/golang-jwt/jwt/v5
```

### Step 2: Create Project Structure

```powershell
# Create directories
mkdir cmd\server
mkdir internal\config
mkdir internal\database
mkdir internal\models
mkdir internal\repository
mkdir internal\services
mkdir internal\handlers
mkdir internal\middleware
mkdir pkg\logger
mkdir pkg\response

# Create main files
New-Item -Path "cmd\server\main.go" -ItemType File
New-Item -Path ".env" -ItemType File
New-Item -Path ".env.example" -ItemType File
New-Item -Path ".gitignore" -ItemType File
```

---

## Project Structure

```
go-task-manager-service/
├── cmd/
│   └── server/
│       └── main.go                 # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go              # Configuration management
│   ├── database/
│   │   ├── database.go            # Database interface
│   │   ├── postgres.go            # PostgreSQL implementation
│   │   └── mssql.go               # SQL Server implementation
│   ├── models/
│   │   ├── user.go
│   │   └── role.go
│   ├── repository/
│   │   └── user_repository.go
│   ├── services/
│   │   └── auth_service.go
│   ├── handlers/
│   │   └── health_handler.go
│   └── middleware/
│       └── logger.go
├── pkg/
│   ├── logger/
│   │   └── logger.go
│   └── response/
│       └── response.go
├── .env                            # Environment variables (gitignored)
├── .env.example                    # Example environment file
├── go.mod
└── go.sum
```

---

## Configuration System

### File: `.env.example`

```env
# Server Configuration
SERVER_PORT=8080
SERVER_HOST=0.0.0.0
SERVER_READ_TIMEOUT=10s
SERVER_WRITE_TIMEOUT=10s

# Database Selection (postgres or mssql)
DB_DRIVER=postgres

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=taskflow_user
POSTGRES_PASSWORD=taskflow_pass123
POSTGRES_DB=taskflow_db
POSTGRES_SSLMODE=disable

# SQL Server Configuration
MSSQL_HOST=localhost
MSSQL_PORT=1433
MSSQL_USER=taskflow_user
MSSQL_PASSWORD=taskflow_pass123
MSSQL_DB=taskflow_db

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h

# Application
APP_ENV=development
LOG_LEVEL=debug
```

### File: `.env`

```env
# Copy from .env.example and set your actual values
# This file should be in .gitignore

DB_DRIVER=postgres
SERVER_PORT=8080

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=taskflow_user
POSTGRES_PASSWORD=taskflow_pass123
POSTGRES_DB=taskflow_db
POSTGRES_SSLMODE=disable

MSSQL_HOST=localhost
MSSQL_PORT=1433
MSSQL_USER=taskflow_user
MSSQL_PASSWORD=taskflow_pass123
MSSQL_DB=taskflow_db

JWT_SECRET=dev-secret-key-change-in-production
JWT_EXPIRY=15m

APP_ENV=development
LOG_LEVEL=debug
```

### File: `internal/config/config.go`

```go
package config

import (
	"time"

	"github.com/spf13/viper"
)

// Config holds all application configuration
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	App      AppConfig
}

type ServerConfig struct {
	Port         string
	Host         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type DatabaseConfig struct {
	Driver   string // "postgres" or "mssql"
	Postgres PostgresConfig
	MSSQL    MSSQLConfig
}

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type MSSQLConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
}

type JWTConfig struct {
	Secret        string
	Expiry        time.Duration
	RefreshExpiry time.Duration
}

type AppConfig struct {
	Environment string
	LogLevel    string
}

// Load reads configuration from environment variables and .env file
func Load() (*Config, error) {
	// Set default values
	viper.SetDefault("SERVER_PORT", "8080")
	viper.SetDefault("SERVER_HOST", "0.0.0.0")
	viper.SetDefault("DB_DRIVER", "postgres")
	viper.SetDefault("APP_ENV", "development")
	viper.SetDefault("LOG_LEVEL", "info")

	// Read from .env file
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		// .env file is optional, so we just log the error
		// Configuration can still work with environment variables
	}

	cfg := &Config{
		Server: ServerConfig{
			Port:         viper.GetString("SERVER_PORT"),
			Host:         viper.GetString("SERVER_HOST"),
			ReadTimeout:  viper.GetDuration("SERVER_READ_TIMEOUT"),
			WriteTimeout: viper.GetDuration("SERVER_WRITE_TIMEOUT"),
		},
		Database: DatabaseConfig{
			Driver: viper.GetString("DB_DRIVER"),
			Postgres: PostgresConfig{
				Host:     viper.GetString("POSTGRES_HOST"),
				Port:     viper.GetString("POSTGRES_PORT"),
				User:     viper.GetString("POSTGRES_USER"),
				Password: viper.GetString("POSTGRES_PASSWORD"),
				DBName:   viper.GetString("POSTGRES_DB"),
				SSLMode:  viper.GetString("POSTGRES_SSLMODE"),
			},
			MSSQL: MSSQLConfig{
				Host:     viper.GetString("MSSQL_HOST"),
				Port:     viper.GetString("MSSQL_PORT"),
				User:     viper.GetString("MSSQL_USER"),
				Password: viper.GetString("MSSQL_PASSWORD"),
				DBName:   viper.GetString("MSSQL_DB"),
			},
		},
		JWT: JWTConfig{
			Secret:        viper.GetString("JWT_SECRET"),
			Expiry:        viper.GetDuration("JWT_EXPIRY"),
			RefreshExpiry: viper.GetDuration("JWT_REFRESH_EXPIRY"),
		},
		App: AppConfig{
			Environment: viper.GetString("APP_ENV"),
			LogLevel:    viper.GetString("LOG_LEVEL"),
		},
	}

	return cfg, nil
}

// GetDatabaseDriver returns the selected database driver
func (c *Config) GetDatabaseDriver() string {
	return c.Database.Driver
}

// IsProduction returns true if running in production
func (c *Config) IsProduction() bool {
	return c.App.Environment == "production"
}
```

---

## Database Connection

### File: `internal/database/database.go`

```go
package database

import (
	"database/sql"
	"fmt"

	"github.com/yourusername/go-task-manager-service/internal/config"
)

// Database interface for database operations
type Database interface {
	Connect() error
	Close() error
	GetDB() *sql.DB
	Ping() error
	GetDriverName() string
}

// NewDatabase creates a new database connection based on configuration
func NewDatabase(cfg *config.Config) (Database, error) {
	switch cfg.Database.Driver {
	case "postgres":
		return NewPostgresDB(cfg), nil
	case "mssql":
		return NewMSSQLDB(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Database.Driver)
	}
}
```

### File: `internal/database/postgres.go`

```go
package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/yourusername/go-task-manager-service/internal/config"
)

// PostgresDB implements Database interface for PostgreSQL
type PostgresDB struct {
	db  *sql.DB
	cfg *config.Config
}

// NewPostgresDB creates a new PostgreSQL database connection
func NewPostgresDB(cfg *config.Config) *PostgresDB {
	return &PostgresDB{
		cfg: cfg,
	}
}

// Connect establishes connection to PostgreSQL
func (p *PostgresDB) Connect() error {
	pgCfg := p.cfg.Database.Postgres
	
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		pgCfg.Host,
		pgCfg.Port,
		pgCfg.User,
		pgCfg.Password,
		pgCfg.DBName,
		pgCfg.SSLMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open postgres connection: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * 60) // 5 minutes

	// Verify connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	p.db = db
	return nil
}

// Close closes the database connection
func (p *PostgresDB) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

// GetDB returns the underlying *sql.DB
func (p *PostgresDB) GetDB() *sql.DB {
	return p.db
}

// Ping checks if database is alive
func (p *PostgresDB) Ping() error {
	return p.db.Ping()
}

// GetDriverName returns the driver name
func (p *PostgresDB) GetDriverName() string {
	return "postgres"
}
```

### File: `internal/database/mssql.go`

```go
package database

import (
	"database/sql"
	"fmt"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/yourusername/go-task-manager-service/internal/config"
)

// MSSQLDB implements Database interface for SQL Server
type MSSQLDB struct {
	db  *sql.DB
	cfg *config.Config
}

// NewMSSQLDB creates a new SQL Server database connection
func NewMSSQLDB(cfg *config.Config) *MSSQLDB {
	return &MSSQLDB{
		cfg: cfg,
	}
}

// Connect establishes connection to SQL Server
func (m *MSSQLDB) Connect() error {
	msCfg := m.cfg.Database.MSSQL
	
	connStr := fmt.Sprintf(
		"sqlserver://%s:%s@%s:%s?database=%s",
		msCfg.User,
		msCfg.Password,
		msCfg.Host,
		msCfg.Port,
		msCfg.DBName,
	)

	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		return fmt.Errorf("failed to open mssql connection: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * 60) // 5 minutes

	// Verify connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping mssql: %w", err)
	}

	m.db = db
	return nil
}

// Close closes the database connection
func (m *MSSQLDB) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// GetDB returns the underlying *sql.DB
func (m *MSSQLDB) GetDB() *sql.DB {
	return m.db
}

// Ping checks if database is alive
func (m *MSSQLDB) Ping() error {
	return m.db.Ping()
}

// GetDriverName returns the driver name
func (m *MSSQLDB) GetDriverName() string {
	return "mssql"
}
```

---

## Running the Server

### File: `pkg/logger/logger.go`

```go
package logger

import (
	"os"

	"github.com/rs/zerolog"
)

var Log zerolog.Logger

// Init initializes the logger
func Init(level string) {
	// Parse log level
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(logLevel)

	// Pretty console output for development
	Log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).
		With().
		Timestamp().
		Caller().
		Logger()
}

// Info logs info message
func Info(msg string) {
	Log.Info().Msg(msg)
}

// Error logs error message
func Error(msg string, err error) {
	Log.Error().Err(err).Msg(msg)
}

// Debug logs debug message
func Debug(msg string) {
	Log.Debug().Msg(msg)
}
```

### File: `pkg/response/response.go`

```go
package response

import (
	"encoding/json"
	"net/http"
)

// Response is the standard API response structure
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// JSON writes a JSON response
func JSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Success writes a success response
func Success(w http.ResponseWriter, message string, data interface{}) {
	JSON(w, http.StatusOK, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// Error writes an error response
func Error(w http.ResponseWriter, status int, message string) {
	JSON(w, status, Response{
		Success: false,
		Error:   message,
	})
}
```

### File: `internal/handlers/health_handler.go`

```go
package handlers

import (
	"net/http"

	"github.com/yourusername/go-task-manager-service/internal/database"
	"github.com/yourusername/go-task-manager-service/pkg/response"
)

// HealthHandler handles health check requests
type HealthHandler struct {
	db database.Database
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(db database.Database) *HealthHandler {
	return &HealthHandler{db: db}
}

// Health checks if the server is running
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	response.Success(w, "Server is running", map[string]string{
		"status": "ok",
	})
}

// HealthDB checks database connection
func (h *HealthHandler) HealthDB(w http.ResponseWriter, r *http.Request) {
	err := h.db.Ping()
	if err != nil {
		response.Error(w, http.StatusServiceUnavailable, "Database connection failed")
		return
	}

	response.Success(w, "Database is connected", map[string]string{
		"status": "ok",
		"driver": h.db.GetDriverName(),
	})
}
```

### File: `cmd/server/main.go`

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/yourusername/go-task-manager-service/internal/config"
	"github.com/yourusername/go-task-manager-service/internal/database"
	"github.com/yourusername/go-task-manager-service/internal/handlers"
	"github.com/yourusername/go-task-manager-service/pkg/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger.Init(cfg.App.LogLevel)
	logger.Info("Starting TaskFlow server...")

	// Connect to database
	db, err := database.NewDatabase(cfg)
	if err != nil {
		logger.Error("Failed to create database", err)
		os.Exit(1)
	}

	if err := db.Connect(); err != nil {
		logger.Error("Failed to connect to database", err)
		os.Exit(1)
	}
	defer db.Close()

	logger.Info(fmt.Sprintf("Connected to %s database successfully", db.GetDriverName()))

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:*", "https://localhost:*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Handlers
	healthHandler := handlers.NewHealthHandler(db)

	// Routes
	r.Get("/health", healthHandler.Health)
	r.Get("/health/db", healthHandler.HealthDB)

	// API routes group
	r.Route("/api", func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("TaskFlow API v1.0"))
		})

		// Auth routes (to be implemented)
		// r.Route("/auth", func(r chi.Router) {
		//     r.Post("/register", authHandler.Register)
		//     r.Post("/login", authHandler.Login)
		// })
	})

	// Create server
	serverAddr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		logger.Info(fmt.Sprintf("Server starting on %s", serverAddr))
		logger.Info(fmt.Sprintf("Using database: %s", cfg.Database.Driver))
		logger.Info(fmt.Sprintf("Environment: %s", cfg.App.Environment))
		
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed to start", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
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
```

---

## Testing Database Connection

### Step 1: Copy Environment File

```powershell
Copy-Item .env.example .env
# Edit .env and set DB_DRIVER to either "postgres" or "mssql"
```

### Step 2: Run the Server

```powershell
# Using PostgreSQL
go run cmd/server/main.go

# Or to explicitly set database driver
$env:DB_DRIVER="postgres"; go run cmd/server/main.go

# To use SQL Server instead
$env:DB_DRIVER="mssql"; go run cmd/server/main.go
```

### Step 3: Test Endpoints

```powershell
# Check server health
curl http://localhost:8080/health

# Check database connection
curl http://localhost:8080/health/db
```

Expected responses:

```json
// GET /health
{
  "success": true,
  "message": "Server is running",
  "data": {
    "status": "ok"
  }
}

// GET /health/db
{
  "success": true,
  "message": "Database is connected",
  "data": {
    "status": "ok",
    "driver": "postgres"
  }
}
```

---

## Switching Between Databases

### Method 1: Using .env File

Edit `.env` and change:
```env
DB_DRIVER=postgres  # or mssql
```

### Method 2: Using Environment Variables

```powershell
# PostgreSQL
$env:DB_DRIVER="postgres"
go run cmd/server/main.go

# SQL Server
$env:DB_DRIVER="mssql"
go run cmd/server/main.go
```

### Method 3: Command Line Flag (Optional Enhancement)

Add flag support in `main.go`:
```go
var dbDriver = flag.String("db", "postgres", "Database driver (postgres or mssql)")
flag.Parse()
```

---

## `.gitignore`

```gitignore
# Binaries
*.exe
*.dll
*.so
*.dylib

# Test binary
*.test

# Output
*.out

# Go workspace file
go.work

# Environment variables
.env

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs
*.log

# Temporary files
tmp/
temp/
```

---

## Next Steps

1. ✅ Initialize Go module
2. ✅ Create configuration system
3. ✅ Implement database connection
4. ✅ Create basic server with health checks
5. ⏳ Implement authentication (see AUTHENTICATION_GUIDE.md)
6. ⏳ Add user management (see USER_MANAGEMENT_GUIDE.md)
7. ⏳ Build business features (see FEATURES_GUIDE.md)

---

## Troubleshooting

### Database Connection Failed

**PostgreSQL:**
```powershell
# Check if PostgreSQL is running
Get-Service postgresql*

# Test connection
psql -U taskflow_user -d taskflow_db
```

**SQL Server:**
```powershell
# Check if SQL Server is running
Get-Service MSSQLSERVER

# Test connection in SSMS
```

### Port Already in Use

```powershell
# Change port in .env
SERVER_PORT=8081
```

### Module Import Errors

```powershell
# Update module name in all imports
# Replace "github.com/yourusername/go-task-manager-service"
# With your actual module name from go.mod
```

---

**You now have a complete Go server that can connect to either PostgreSQL or SQL Server based on configuration!**
