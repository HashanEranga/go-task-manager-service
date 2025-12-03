# Go Task Manager Service - Manual Setup Guide

Complete step-by-step manual setup workflow for creating a Go server with dual database support (PostgreSQL and SQL Server).

## 📋 Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Phase 1: Initialize Go Module](#phase-1-initialize-go-module)
4. [Phase 2: Create Directory Structure](#phase-2-create-directory-structure)
5. [Phase 3: Create Configuration Files](#phase-3-create-configuration-files)
6. [Phase 4: Create Go Source Files](#phase-4-create-go-source-files)
7. [Phase 5: Run and Test](#phase-5-run-and-test)
8. [Switching Between Databases](#switching-between-databases)
9. [Troubleshooting](#troubleshooting)

---

## Overview

This guide will help you manually set up a production-ready Go server that supports:
- ✅ Dual database support (PostgreSQL and SQL Server)
- ✅ Environment-based configuration
- ✅ Health check endpoints
- ✅ Structured logging
- ✅ CORS support
- ✅ Graceful shutdown
- ✅ Connection pooling

**Estimated Time:** 30-45 minutes

---

## Prerequisites

Before starting, ensure you have:

- ✅ Go 1.21+ installed
- ✅ PostgreSQL 15+ installed and running
- ✅ SQL Server 2022 installed and running (optional)
- ✅ Basic knowledge of Go and PowerShell
- ✅ Database created (taskflow_db) with user (taskflow_user)

---

## Phase 1: Initialize Go Module

### Step 1.1: Navigate to Project Directory

```powershell
cd C:\Users\HashanEranga\Documents\projects\goApps\go-task-manager-service
```

### Step 1.2: Initialize Go Module

```powershell
go mod init github.com/HashanEranga/go-task-manager-service
```

**Expected Output:**
```
go: creating new go.mod: module github.com/HashanEranga/go-task-manager-service
```

### Step 1.3: Install Required Dependencies

Run each command one by one:

```powershell
# Web Framework
go get github.com/go-chi/chi/v5

# CORS Middleware
go get github.com/go-chi/cors

# PostgreSQL Driver
go get github.com/lib/pq

# SQL Server Driver
go get github.com/denisenkom/go-mssqldb

# Configuration Management
go get github.com/spf13/viper

# Logging
go get github.com/rs/zerolog

# Environment Variables
go get github.com/joho/godotenv

# Password Hashing
go get golang.org/x/crypto/bcrypt

# JWT Authentication
go get github.com/golang-jwt/jwt/v5
```

**Tip:** You can run all at once by separating with semicolons:
```powershell
go get github.com/go-chi/chi/v5; go get github.com/go-chi/cors; go get github.com/lib/pq; go get github.com/denisenkom/go-mssqldb; go get github.com/spf13/viper; go get github.com/rs/zerolog; go get github.com/joho/godotenv; go get golang.org/x/crypto/bcrypt; go get github.com/golang-jwt/jwt/v5
```

---

## Phase 2: Create Directory Structure

### Step 2.1: Create All Directories

```powershell
# Create main application directories
mkdir cmd\server

# Create internal packages
mkdir internal\config
mkdir internal\database
mkdir internal\models
mkdir internal\repository
mkdir internal\services
mkdir internal\handlers
mkdir internal\middleware

# Create public packages
mkdir pkg\logger
mkdir pkg\response
```

### Step 2.2: Create Placeholder Files

```powershell
# Create main files
New-Item -Path "cmd\server\main.go" -ItemType File -Force

# Create config files
New-Item -Path "internal\config\config.go" -ItemType File -Force

# Create database files
New-Item -Path "internal\database\database.go" -ItemType File -Force
New-Item -Path "internal\database\postgres.go" -ItemType File -Force
New-Item -Path "internal\database\mssql.go" -ItemType File -Force

# Create handler files
New-Item -Path "internal\handlers\health_handler.go" -ItemType File -Force

# Create utility files
New-Item -Path "pkg\logger\logger.go" -ItemType File -Force
New-Item -Path "pkg\response\response.go" -ItemType File -Force

# Create environment files
New-Item -Path ".env" -ItemType File -Force
New-Item -Path ".env.example" -ItemType File -Force
New-Item -Path ".gitignore" -ItemType File -Force
```

**Expected Structure:**
```
go-task-manager-service/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── config/
│   │   └── config.go
│   ├── database/
│   │   ├── database.go
│   │   ├── postgres.go
│   │   └── mssql.go
│   ├── handlers/
│   │   └── health_handler.go
│   ├── models/
│   ├── repository/
│   ├── services/
│   └── middleware/
├── pkg/
│   ├── logger/
│   │   └── logger.go
│   └── response/
│       └── response.go
├── .env
├── .env.example
├── .gitignore
├── go.mod
└── go.sum
```

---

## Phase 3: Create Configuration Files

### File 1: `.gitignore`

Create `.gitignore` and add:

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

### File 2: `.env.example`

Create `.env.example` and add:

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

### File 3: `.env`

Copy from `.env.example` or create with your actual database credentials:

```env
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

**Important:** Make sure to update the database credentials to match your setup!

---

## Phase 4: Create Go Source Files

### File 1: `internal/config/config.go`

Open `internal/config/config.go` and add:

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

### File 2: `internal/database/database.go`

Open `internal/database/database.go` and add:

```go
package database

import (
	"database/sql"
	"fmt"

	"github.com/HashanEranga/go-task-manager-service/internal/config"
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

### File 3: `internal/database/postgres.go`

Open `internal/database/postgres.go` and add:

```go
package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/HashanEranga/go-task-manager-service/internal/config"
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
	db.SetConnMaxLifetime(5 * time.Minute)

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

### File 4: `internal/database/mssql.go`

Open `internal/database/mssql.go` and add:

```go
package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/HashanEranga/go-task-manager-service/internal/config"
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
	db.SetConnMaxLifetime(5 * time.Minute)

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

### File 5: `pkg/logger/logger.go`

Open `pkg/logger/logger.go` and add:

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

### File 6: `pkg/response/response.go`

Open `pkg/response/response.go` and add:

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

### File 7: `internal/handlers/health_handler.go`

Open `internal/handlers/health_handler.go` and add:

```go
package handlers

import (
	"net/http"

	"github.com/HashanEranga/go-task-manager-service/internal/database"
	"github.com/HashanEranga/go-task-manager-service/pkg/response"
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

### File 8: `cmd/server/main.go`

Open `cmd/server/main.go` and add:

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

	"github.com/HashanEranga/go-task-manager-service/internal/config"
	"github.com/HashanEranga/go-task-manager-service/internal/database"
	"github.com/HashanEranga/go-task-manager-service/internal/handlers"
	"github.com/HashanEranga/go-task-manager-service/pkg/logger"
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

## Phase 5: Run and Test

### Step 5.1: Tidy Dependencies

```powershell
go mod tidy
```

**Expected Output:**
```
go: downloading github.com/go-chi/chi/v5 v5.x.x
go: downloading github.com/go-chi/cors v1.x.x
...
```

### Step 5.2: Run Server with PostgreSQL

```powershell
# Option 1: Using .env file (ensure DB_DRIVER=postgres in .env)
go run cmd/server/main.go

# Option 2: Override with environment variable
$env:DB_DRIVER="postgres"; go run cmd/server/main.go
```

**Expected Console Output:**
```
2:30PM INF Starting TaskFlow server...
2:30PM INF Connected to postgres database successfully
2:30PM INF Server starting on 0.0.0.0:8080
2:30PM INF Using database: postgres
2:30PM INF Environment: development
```

### Step 5.3: Test Endpoints

Open a new PowerShell window and run:

```powershell
# Test server health
curl http://localhost:8080/health

# Test database connection
curl http://localhost:8080/health/db

# Test API endpoint
curl http://localhost:8080/api/
```

**Expected Responses:**

**GET /health:**
```json
{
  "success": true,
  "message": "Server is running",
  "data": {
    "status": "ok"
  }
}
```

**GET /health/db:**
```json
{
  "success": true,
  "message": "Database is connected",
  "data": {
    "status": "ok",
    "driver": "postgres"
  }
}
```

**GET /api/:**
```
TaskFlow API v1.0
```

### Step 5.4: Test with SQL Server (Optional)

Stop the server (Ctrl+C) and restart with SQL Server:

```powershell
$env:DB_DRIVER="mssql"; go run cmd/server/main.go
```

Test the `/health/db` endpoint again - it should now show `"driver": "mssql"`

---

## Switching Between Databases

### Method 1: Edit `.env` File

Open `.env` and change:
```env
DB_DRIVER=postgres   # or mssql
```

Restart the server:
```powershell
go run cmd/server/main.go
```

### Method 2: Environment Variable Override

```powershell
# PostgreSQL
$env:DB_DRIVER="postgres"
go run cmd/server/main.go

# SQL Server
$env:DB_DRIVER="mssql"
go run cmd/server/main.go
```

### Method 3: Command-Line Override (PowerShell)

```powershell
# Single-line execution
$env:DB_DRIVER="postgres"; go run cmd/server/main.go
```

---

## Troubleshooting

### Issue 1: "failed to connect to database"

**Symptoms:**
```
ERR Failed to connect to database error="failed to ping postgres: ..."
```

**Solutions:**

1. **Check if database is running:**
   ```powershell
   # PostgreSQL
   Get-Service postgresql*
   
   # SQL Server
   Get-Service MSSQLSERVER
   ```

2. **Start the service if stopped:**
   ```powershell
   # PostgreSQL
   Start-Service postgresql-x64-15
   
   # SQL Server
   Start-Service MSSQLSERVER
   ```

3. **Verify database exists:**
   ```powershell
   # PostgreSQL
   psql -U postgres -c "\l" | Select-String taskflow_db
   
   # SQL Server (in SSMS)
   SELECT name FROM sys.databases WHERE name = 'taskflow_db'
   ```

4. **Check credentials in `.env` file:**
   - Ensure username and password match your database setup
   - Verify database name is correct

### Issue 2: "Port already in use"

**Symptoms:**
```
ERR Server failed to start error="listen tcp :8080: bind: Only one usage of each socket address..."
```

**Solutions:**

1. **Change the port in `.env`:**
   ```env
   SERVER_PORT=8081
   ```

2. **Find and kill the process using port 8080:**
   ```powershell
   # Find process
   netstat -ano | findstr :8080
   
   # Kill process (replace PID with actual process ID)
   taskkill /PID <PID> /F
   ```

### Issue 3: Import Errors

**Symptoms:**
```
package github.com/go-chi/chi/v5 is not in GOROOT
```

**Solutions:**

1. **Run go mod tidy:**
   ```powershell
   go mod tidy
   ```

2. **Manually download missing packages:**
   ```powershell
   go get github.com/go-chi/chi/v5
   ```

3. **Clear module cache if needed:**
   ```powershell
   go clean -modcache
   go mod tidy
   ```

### Issue 4: ".env file not found" (Warning)

**Symptoms:**
```
WARN Could not read .env file
```

**Solutions:**

1. **This is just a warning - the app will still work with default values**

2. **To fix, create `.env` file:**
   ```powershell
   Copy-Item .env.example .env
   ```

### Issue 5: Connection Timeout

**Symptoms:**
```
failed to ping postgres: dial tcp: i/o timeout
```

**Solutions:**

1. **Check firewall settings**
2. **Verify database host and port in `.env`**
3. **Test connection manually:**
   ```powershell
   # PostgreSQL
   psql -U taskflow_user -d taskflow_db -h localhost
   
   # SQL Server (in SSMS)
   # Connect to: localhost,1433
   ```

### Issue 6: Authentication Failed

**Symptoms:**
```
failed to ping postgres: password authentication failed
```

**Solutions:**

1. **Reset database user password:**
   ```sql
   -- PostgreSQL
   ALTER USER taskflow_user WITH PASSWORD 'taskflow_pass123';
   
   -- SQL Server
   ALTER LOGIN taskflow_user WITH PASSWORD = 'taskflow_pass123';
   ```

2. **Update `.env` file with correct password**

---

## Next Steps

### ✅ Phase 1 Complete: Basic Server Setup
You now have:
- Working Go server
- Dual database support
- Health check endpoints
- Configuration management
- Structured logging

### 🚀 Phase 2: Add Authentication
Next, you'll implement:
- User registration
- Login with JWT
- Password hashing
- Token refresh
- Logout functionality

**See:** `docs/AUTHENTICATION_GUIDE.md` (to be created)

### 📊 Phase 3: Add Business Features
After authentication:
- Project management
- Task CRUD operations
- User assignments
- File uploads
- Comments and collaboration

---

## Verification Checklist

Use this checklist to ensure everything is working:

- [ ] Go module initialized (`go.mod` exists)
- [ ] All dependencies installed (no import errors)
- [ ] Directory structure created
- [ ] All 8 source files created and populated
- [ ] `.env` file configured with correct database credentials
- [ ] `.gitignore` file created
- [ ] Server starts without errors
- [ ] `/health` endpoint returns success
- [ ] `/health/db` endpoint shows database connection
- [ ] Can switch between PostgreSQL and SQL Server
- [ ] Graceful shutdown works (Ctrl+C)

---

## Quick Reference

### Common Commands

```powershell
# Run server
go run cmd/server/main.go

# Run with specific database
$env:DB_DRIVER="postgres"; go run cmd/server/main.go
$env:DB_DRIVER="mssql"; go run cmd/server/main.go

# Build executable
go build -o taskflow.exe cmd/server/main.go

# Run executable
.\taskflow.exe

# Update dependencies
go mod tidy

# Test endpoints
curl http://localhost:8080/health
curl http://localhost:8080/health/db
curl http://localhost:8080/api/
```

### Project Structure Quick View

```
go-task-manager-service/
├── cmd/server/main.go              # Entry point
├── internal/
│   ├── config/config.go            # Configuration
│   ├── database/                   # Database layer
│   │   ├── database.go            # Interface
│   │   ├── postgres.go            # PostgreSQL impl
│   │   └── mssql.go               # SQL Server impl
│   └── handlers/                   # HTTP handlers
│       └── health_handler.go      # Health checks
├── pkg/
│   ├── logger/logger.go           # Logging utility
│   └── response/response.go       # Response helpers
├── .env                            # Environment config
├── .env.example                    # Config template
├── .gitignore                      # Git ignore rules
├── go.mod                          # Go module file
└── go.sum                          # Dependency checksums
```

---

## Summary

Congratulations! 🎉 You've successfully set up a production-ready Go server with:

- ✅ **Dual Database Support** - Switch between PostgreSQL and SQL Server
- ✅ **Clean Architecture** - Organized, maintainable code structure
- ✅ **Configuration Management** - Environment-based config with Viper
- ✅ **Health Checks** - Monitor server and database status
- ✅ **Structured Logging** - Beautiful console logs with Zerolog
- ✅ **CORS Support** - Ready for frontend integration
- ✅ **Graceful Shutdown** - Clean server termination
- ✅ **Connection Pooling** - Optimized database performance

**Total Setup Time:** 30-45 minutes

**Next:** Add authentication and start building your API!

---

**Need Help?**
- Check the troubleshooting section above
- Review `docs/DATABASE_SETUP.md` for database issues
- See `docs/GO_APPLICATION_SETUP.md` for more details

**Found a bug or have suggestions?**
- Create an issue in the project repository
- Update this documentation with improvements
