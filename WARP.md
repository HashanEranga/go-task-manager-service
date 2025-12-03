# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

**TaskFlow** is a production-ready Go backend service for task and project management with JWT authentication, RBAC authorization, and dual database support (PostgreSQL & SQL Server).

### Current Implementation Status
- ✅ **Phase 1 Complete**: Database schema (7 foundation tables) and Liquibase migrations
- 🚧 **Phase 2 In Progress**: Go application structure (config, database abstraction, basic handlers)
- ⏳ **Phase 3+**: Authentication API, business logic (projects, tasks, collaboration features)

## Development Commands

### Database Management

#### Setup Databases (First Time)
```powershell
# PostgreSQL
psql -U postgres -c "CREATE DATABASE taskflow_db;"
psql -U postgres -c "CREATE USER taskflow_user WITH PASSWORD 'taskflow_pass123';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE taskflow_db TO taskflow_user;"

# SQL Server (in SSMS)
# CREATE DATABASE taskflow_db;
# CREATE LOGIN taskflow_user WITH PASSWORD = 'taskflow_pass123';
# CREATE USER taskflow_user FOR LOGIN taskflow_user;
# GRANT CONTROL ON DATABASE::taskflow_db TO taskflow_user;
```

#### Run Migrations
```powershell
# PostgreSQL migrations
cd migrations\postgresql
liquibase update

# SQL Server migrations
cd migrations\mssql
liquibase update
```

#### Verify Database Setup
```powershell
# PostgreSQL - should show 7 tables
psql -U taskflow_user -d taskflow_db -c "\dt"

# Check default admin account exists
psql -U taskflow_user -d taskflow_db -c "SELECT username, email FROM users;"
```

### Go Application

#### Build and Run
```powershell
# Initialize dependencies (first time)
go mod tidy

# Build the application
go build -o bin/taskflow.exe cmd/server/main.go

# Run the application
go run cmd/server/main.go
```

#### Testing
```powershell
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests for specific package
go test ./internal/config
go test ./internal/database
```

#### Code Quality
```powershell
# Format code
go fmt ./...

# Run linter (if golangci-lint is installed)
golangci-lint run

# Vet code for issues
go vet ./...
```

## Architecture

### Project Structure
```
go-task-manager-service/
├── cmd/server/main.go          # Application entry point
├── internal/                   # Private application code
│   ├── config/                 # Configuration management (Viper)
│   ├── database/              # Database abstraction layer
│   │   ├── database.go        # Database interface
│   │   ├── postgres.go        # PostgreSQL implementation
│   │   └── mssql.go           # SQL Server implementation
│   ├── handlers/              # HTTP request handlers
│   ├── middleware/            # (To be added) Auth, logging, CORS
│   ├── models/                # (To be added) Domain models
│   ├── repository/            # (To be added) Data access layer
│   └── services/              # (To be added) Business logic
├── pkg/                       # Public libraries
│   ├── logger/                # Logging utilities (zerolog)
│   └── response/              # HTTP response helpers
├── migrations/                # Liquibase database migrations
│   ├── postgresql/
│   └── mssql/
└── docs/                      # Comprehensive documentation
```

### Database Layer Architecture

The application supports dual database drivers through an abstraction layer:

1. **Database Interface** (`internal/database/database.go`): Defines common operations (Connect, Close, GetDB, Ping, GetDriverName)
2. **Driver Selection**: Based on `DB_DRIVER` env var (`postgres` or `mssql`)
3. **Connection Pooling**: Both drivers configured with:
   - MaxOpenConns: 25
   - MaxIdleConns: 5
   - ConnMaxLifetime: 5 minutes

### Configuration Management

- Uses **Viper** for configuration loading
- Loads from `.env` file + environment variables
- Configuration structure in `internal/config/config.go`:
  - ServerConfig: Port, host, timeouts
  - DatabaseConfig: Driver selection + connection details for both PostgreSQL and MSSQL
  - JWTConfig: Secret, expiry durations
  - AppConfig: Environment, log level

### Database Schema (Foundation)

7 tables provide authentication and RBAC foundation:
1. **users**: User accounts with bcrypt passwords, email verification, account locking
2. **roles**: Role definitions (ADMIN, USER, MODERATOR, GUEST)
3. **permissions**: Granular permissions (format: `resource.action` e.g., `users.read`)
4. **user_roles**: Many-to-many user ↔ roles
5. **role_permissions**: Many-to-many roles ↔ permissions
6. **refresh_tokens**: JWT refresh token storage with revocation support
7. **audit_logs**: Activity tracking (action, resource, old/new values, IP, user agent)

**Default Credentials** (created by migrations):
- Username: `admin`
- Password: `Admin@123`
- Email: `admin@example.com`
- Role: ADMIN (full permissions)

## Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Required: Database driver selection
DB_DRIVER=postgres  # or "mssql"

# Required: PostgreSQL config (if using postgres)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=taskflow_user
POSTGRES_PASSWORD=taskflow_pass123
POSTGRES_DB=taskflow_db
POSTGRES_SSLMODE=disable

# Required: SQL Server config (if using mssql)
MSSQL_HOST=localhost
MSSQL_PORT=1433
MSSQL_USER=taskflow_user
MSSQL_PASSWORD=taskflow_pass123
MSSQL_DB=taskflow_db

# Required: JWT configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h

# Optional: Server and app config
SERVER_PORT=8080
APP_ENV=development
LOG_LEVEL=debug
```

## Technology Stack

### Core Dependencies (from go.mod)
- **Web Framework**: `github.com/go-chi/chi/v5` (v5.2.3) - HTTP router
- **Configuration**: `github.com/spf13/viper` (v1.21.0) - Config management
- **Database Drivers**:
  - PostgreSQL: `github.com/lib/pq` (v1.10.9)
  - SQL Server: `github.com/denisenkom/go-mssqldb` (v0.12.3)
- **Authentication**: `github.com/golang-jwt/jwt/v5` (v5.3.0) - JWT tokens
- **Logging**: `github.com/rs/zerolog` (v1.34.0) - Structured logging
- **CORS**: `github.com/go-chi/cors` (v1.2.2)
- **Security**: `golang.org/x/crypto` (v0.45.0) - Bcrypt password hashing

## Important Implementation Notes

### Database Connection Pattern
When implementing repository or service layers:
```go
// Get database from factory
db, err := database.NewDatabase(cfg)
if err != nil {
    // handle error
}
defer db.Close()

// Use database
sqlDB := db.GetDB() // Returns *sql.DB for queries
```

### RBAC Permission Format
Permissions follow the pattern: `resource.action`
- Resources: `users`, `roles`, `permissions`, `projects`, `tasks`, etc.
- Actions: `read`, `create`, `update`, `delete`, `manage`
- Examples: `users.read`, `tasks.create`, `projects.delete`

### Typo Alert
There's a typo in `internal/database/postgres.go` line 1: `package databsase` should be `package database`

### Planned Future Modules
When implementing new features, these modules are expected:
- **Projects**: Workspaces/project management
- **Tasks**: Work items with status workflow, assignments
- **Comments**: Task discussions and collaboration
- **Attachments**: File upload/download management
- **Notifications**: User alerts and activity feeds
- **Labels/Tags**: Task categorization
- **WebSockets**: Real-time updates (future phase)

## Testing Guidelines

### Test File Locations
- Unit tests: Place `*_test.go` files alongside source files
- Integration tests: Create `tests/integration/` directory
- Test database: Use separate test database (`taskflow_db_test`)

### Running Specific Tests
```powershell
# Test config package
go test -v ./internal/config

# Test database connections
go test -v ./internal/database

# Run with race detection
go test -race ./...
```

## Migration Management

### Creating New Migrations
1. Create XML changeset in `migrations/postgresql/changelogs/` and `migrations/mssql/changelogs/`
2. Follow naming: `NNN-description.xml` (e.g., `009-create-projects-table.xml`)
3. Add changeset reference to `changelog-master.xml`
4. Test on both databases

### Migration Best Practices
- Always create migrations for both PostgreSQL and SQL Server
- Use database-agnostic Liquibase changesets where possible
- Include rollback changesets for production safety
- Test migrations on clean database before committing

## Documentation

Comprehensive documentation is in the `docs/` folder:
- **docs/PROJECT_README.md**: Complete project overview and roadmap
- **docs/QUICK_START.md**: Fast-track setup guide
- **docs/DATABASE_SETUP.md**: Detailed database installation
- **docs/DATABASE_SCHEMA.md**: Complete schema with ER diagrams
- **docs/IMPLEMENTATION_GUIDE.md**: Step-by-step implementation walkthrough
- **docs/PROJECT_STATUS.md**: Current implementation status

## Common Troubleshooting

### Liquibase Migration Fails
1. Verify JDBC drivers are in `C:\liquibase\lib\`
2. Check database connection in `liquibase.properties`
3. Ensure database user has correct permissions

### Database Connection Fails
1. Verify database is running: `psql -U postgres` or check SQL Server service
2. Check credentials in `.env` match database setup
3. For PostgreSQL, ensure `POSTGRES_SSLMODE=disable` for local development
4. For MSSQL, verify SQL Server authentication mode allows SQL logins

### Go Module Issues
```powershell
# Clean module cache
go clean -modcache

# Re-download dependencies
go mod download

# Verify dependencies
go mod verify
```
