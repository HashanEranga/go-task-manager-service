# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TaskFlow is a Go-based task management system with JWT authentication, RBAC authorization, and dual database support (PostgreSQL/MSSQL). The project uses GORM for database operations and follows a clean architecture pattern.

**Current Status**: Authentication service and user management CRUD completed. Ready for Phase 5.

## Common Commands

### Development
```bash
# Run the server
go run cmd/server/main.go

# Build the application
go build -o bin/taskflow.exe cmd/server/main.go

# Run tests
go test ./...

# Install dependencies
go mod download
go mod tidy
```

### Database
```bash
# Run PostgreSQL migrations
cd migrations/postgresql
liquibase update

# Run SQL Server migrations
cd migrations/mssql
liquibase update
```

### Database Access
- **Database Name**: `taskflow_db`
- **Username**: `taskflow_user`
- **Password**: `taskflow_pass123`
- **Default Admin**: username=`admin`, password=`Admin@123`

## Architecture

### Layer Structure

The application follows a strict layered architecture:

1. **Handler Layer** (`internal/handlers/`) - HTTP request handling and response formatting
2. **Service Layer** (`internal/services/`) - Business logic and orchestration
3. **Repository Layer** (`internal/repository/`) - Database operations using GORM
4. **Models Layer** (`internal/models/`) - Domain models and DTOs

**Critical Rule**: Each layer only communicates with the layer directly below it. Never skip layers (e.g., handlers cannot call repositories directly).

### Database Strategy

The application uses **GORM with existing Liquibase-managed schema**:

- **DO NOT** use GORM's AutoMigrate - schema is managed by Liquibase
- **DO NOT** modify the database schema through GORM
- **DO** use GORM tags that match the existing schema
- All model structs must implement `TableName()` to map to existing tables
- To change schema: update Liquibase changelogs in `migrations/`

### Dual Database Support

The codebase supports both PostgreSQL and SQL Server via the `DB_DRIVER` environment variable:

- Database selection is configured in `.env` file
- Connection logic is in `internal/database/gorm_database.go`
- GORM automatically handles SQL dialect differences
- Repository layer code is database-agnostic

### Authentication & Authorization

- **JWT-based authentication** with access and refresh tokens
- **Access token expiry**: 15 minutes (configurable via `JWT_EXPIRY`)
- **Refresh token expiry**: 7 days (configurable via `JWT_REFRESH_EXPIRY`)
- **RBAC model**: Users → Roles → Permissions (many-to-many relationships)
- **Account security**: Failed login tracking, account locking after 5 failed attempts
- **Audit logging**: All auth events are logged to `audit_logs` table

### Key Security Features

1. **Password validation** (`pkg/security/password.go`):
   - Minimum 8 characters
   - Must contain uppercase, lowercase, number, and special character
   - Bcrypt hashing with cost factor 10

2. **Token management** (`pkg/jwt/jwt.go`):
   - Access tokens include user ID, username, email, roles, and permissions
   - Refresh tokens stored in database with IP address and user agent
   - Token revocation supported

3. **Account protection**:
   - 5 failed login attempts → 15 minute account lock
   - Inactive accounts cannot login
   - Account locked status checked on each login

## Configuration

Configuration is loaded via Viper from `.env` file with these key variables:

```bash
# Server
SERVER_PORT=8080
SERVER_HOST=0.0.0.0

# Database (postgres or mssql)
DB_DRIVER=postgres

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=taskflow_user
POSTGRES_PASSWORD=taskflow_pass123
POSTGRES_DB=taskflow_db
POSTGRES_SSLMODE=disable

# SQL Server
MSSQL_HOST=localhost
MSSQL_PORT=62440
MSSQL_USER=taskflow_user
MSSQL_PASSWORD=taskflow_pass123
MSSQL_DB=taskflow_db

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h

# Application
APP_ENV=development
LOG_LEVEL=debug
```

Configuration loading is in `internal/config/config.go`.

## Important Patterns

### Repository Pattern with GORM

All database access goes through repositories that use GORM:

```go
// Correct - using GORM methods
func (r *UserRepository) FindByUsername(username string) (*models.User, error) {
    var user models.User
    result := r.db.Where("username = ?", username).First(&user)
    if result.Error != nil {
        if errors.Is(result.Error, gorm.ErrRecordNotFound) {
            return nil, ErrUserNotFound
        }
        return nil, result.Error
    }
    return &user, nil
}
```

**Common GORM operations**:
- `Create()` - insert new records
- `First()` - find single record
- `Where()` - filter queries
- `Preload()` - eager load relationships
- `Updates()` - update multiple fields
- `Delete()` - soft/hard delete

### Error Handling

The codebase uses custom error types for domain errors:

```go
var (
    ErrUserNotFound       = errors.New("user not found")
    ErrInvalidCredentials = errors.New("invalid username or password")
    ErrAccountLocked      = errors.New("account is locked")
)
```

Handlers should check for specific errors and return appropriate HTTP status codes.

### Response Format

Use the `pkg/response` package for consistent JSON responses:

```go
// Success
response.JSON(w, http.StatusOK, data)

// Error
response.Error(w, http.StatusBadRequest, "error message", err)
```

### Middleware Usage

Authentication middleware (`internal/middleware/auth_middleware.go`) extracts JWT claims and adds to request context:

```go
// In handlers, retrieve user info from context
userID, ok := r.Context().Value("user_id").(int64)
username := r.Context().Value("username").(string)
```

## Current Implementation Status

**Completed Phases**:

### Phase 1-3: Foundation & Authentication
- ✅ Database schema (7 tables) via Liquibase
- ✅ Configuration management with Viper
- ✅ Database abstraction layer with GORM
- ✅ Authentication service (register, login, refresh, logout)
- ✅ JWT token management
- ✅ Password hashing and validation
- ✅ Audit logging
- ✅ RBAC foundation (roles and permissions)
- ✅ Authentication middleware
- ✅ Health check endpoints

### Phase 4: User Management CRUD ✅
- ✅ Permission-based authorization middleware (`RequirePermission`)
- ✅ User CRUD operations (Create, Read, Update, Delete)
- ✅ User listing with pagination and filtering
- ✅ User activation/deactivation
- ✅ Role assignment and revocation
- ✅ User management endpoints (`/api/users/*`)

**Remaining Phases**:

### Phase 5: Role & Permission Management
- ⏳ Role CRUD operations
- ⏳ Permission CRUD operations
- ⏳ Assign/revoke permissions to roles
- ⏳ Role management endpoints

### Phase 6: Projects Module
- ⏳ Project CRUD operations
- ⏳ Project ownership and access control
- ⏳ Project member management

### Phase 7: Tasks Module
- ⏳ Task CRUD operations
- ⏳ Task assignment and status management
- ⏳ Task dependencies and workflows
- ⏳ Task filtering and sorting

### Phase 8: Collaboration Features
- ⏳ Comments system
- ⏳ File attachments
- ⏳ Activity feeds and notifications

## Database Schema

The application has 7 core tables (managed by Liquibase):

1. **users** - User accounts with authentication fields
2. **roles** - Role definitions (e.g., ADMIN, USER)
3. **permissions** - Permission definitions (e.g., user:create)
4. **user_roles** - Many-to-many: users ↔ roles
5. **role_permissions** - Many-to-many: roles ↔ permissions
6. **refresh_tokens** - JWT refresh token storage
7. **audit_logs** - Audit trail for all operations


## Model Relationships

GORM handles relationships automatically when properly configured:

```go
type User struct {
    ID    int64
    // ... fields ...
    Roles         []Role         `gorm:"many2many:user_roles;"`
    RefreshTokens []RefreshToken `gorm:"foreignKey:UserID"`
    AuditLogs     []AuditLog     `gorm:"foreignKey:UserID"`
}
```

To load relationships: `db.Preload("Roles.Permissions").First(&user, id)`

## Testing

### Manual API Testing (PowerShell)

```powershell
# Register
$body = @{
    username = "testuser"
    email = "test@example.com"
    password = "Test@123456"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/auth/register" -Method Post -Body $body -ContentType "application/json"

# Login
$loginBody = @{
    username = "testuser"
    password = "Test@123456"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
$token = $response.access_token

# Access protected endpoint
$headers = @{ "Authorization" = "Bearer $token" }
Invoke-RestMethod -Uri "http://localhost:8080/api/auth/me" -Method Get -Headers $headers
```

HTTP request examples are available in `requests/` directory.

## Logging

Centralized logging is in `pkg/logger/logger.go` using zerolog:

```go
logger.Info("message")
logger.Error("message", err)
logger.Debug("message")
```

Log level is configured via `LOG_LEVEL` environment variable.

## Adding New Features

When adding new features:

1. **Create models** in `internal/models/` with GORM tags matching schema
2. **Create repository** in `internal/repository/` for database operations
3. **Create service** in `internal/services/` for business logic
4. **Create handler** in `internal/handlers/` for HTTP endpoints
5. **Wire up routes** in `cmd/server/main.go`
6. **Add audit logging** for important operations
7. **Update middleware** if new authorization rules needed

## Common Issues

**GORM Preload not working**: Ensure relationship tags are correct and use `Preload()` before query.

**Database connection fails**: Check `.env` file has correct credentials and database exists.

**JWT token invalid**: Verify `JWT_SECRET` is set and tokens haven't expired.

**Account locked**: Check `locked_until` field in users table or wait 15 minutes.

**Migration issues**: Ensure Liquibase properties files point to correct database and credentials match `.env`.
