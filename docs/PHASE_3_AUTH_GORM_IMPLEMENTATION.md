# Phase 3: Authentication & Authorization with GORM

## Overview
This guide implements Phase 3 using **GORM** (Go Object-Relational Mapping), which significantly reduces boilerplate code and handles database abstraction automatically.

## Prerequisites
- ✅ Database setup complete (PostgreSQL or SQL Server)
- ✅ Go application structure ready
- ✅ Liquibase migrations already run (tables exist)

## GORM Benefits
- ✅ **Auto database dialect detection** (PostgreSQL/MSSQL)
- ✅ **80% less code** than raw SQL
- ✅ **Type-safe queries**
- ✅ **Auto-relationship loading**
- ✅ **Built-in hooks and validations**
- ✅ **Query builder with chainable methods**

---

## Implementation Checklist

### Task 0: Install GORM Dependencies

#### 0.1 Install GORM packages
```powershell
# Core GORM
go get -u gorm.io/gorm

# PostgreSQL driver
go get -u gorm.io/driver/postgres

# SQL Server driver
go get -u gorm.io/driver/sqlserver

# Go JWT
go get -u github.com/golang-jwt/jwt/v5

# Run tidy
go mod tidy
```

**Verification**:
```powershell
go mod verify
```

---

### Task 1: Update Database Connection

#### 1.1 Create `internal/database/gorm_database.go`
```go
package database

import (
	"fmt"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type GormDatabase struct {
	db         *gorm.DB
	driverName string
}

// NewGormDatabase creates a new GORM database connection
func NewGormDatabase(cfg *config.Config) (Database, error) {
	var dialector gorm.Dialector
	var driverName string

	switch cfg.Database.Driver {
	case "postgres":
		dsn := fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			cfg.Database.Postgres.Host,
			cfg.Database.Postgres.Port,
			cfg.Database.Postgres.User,
			cfg.Database.Postgres.Password,
			cfg.Database.Postgres.Database,
			cfg.Database.Postgres.SSLMode,
		)
		dialector = postgres.Open(dsn)
		driverName = "postgres"

	case "mssql":
		dsn := fmt.Sprintf(
			"sqlserver://%s:%s@%s:%s?database=%s",
			cfg.Database.MSSQL.User,
			cfg.Database.MSSQL.Password,
			cfg.Database.MSSQL.Host,
			cfg.Database.MSSQL.Port,
			cfg.Database.MSSQL.Database,
		)
		dialector = sqlserver.Open(dsn)
		driverName = "mssql"

	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Database.Driver)
	}

	// GORM configuration
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	}

	db, err := gorm.Open(dialector, gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying *sql.DB for connection pooling
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// Connection pool settings
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	return &GormDatabase{
		db:         db,
		driverName: driverName,
	}, nil
}

func (g *GormDatabase) Connect() error {
	// Connection already established in constructor
	return nil
}

func (g *GormDatabase) Close() error {
	sqlDB, err := g.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (g *GormDatabase) GetDB() interface{} {
	return g.db
}

func (g *GormDatabase) GetGormDB() *gorm.DB {
	return g.db
}

func (g *GormDatabase) Ping() error {
	sqlDB, err := g.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func (g *GormDatabase) GetDriverName() string {
	return g.driverName
}
```

#### 1.2 Update `internal/database/database.go`
Add method to interface:
```go
package database

import (
	"github.com/HashanEranga/go-task-manager-service/internal/config"
	"gorm.io/gorm"
)

type Database interface {
	Connect() error
	Close() error
	GetDB() interface{}
	GetGormDB() *gorm.DB  // Add this
	Ping() error
	GetDriverName() string
}

// Update factory function
func NewDatabase(cfg *config.Config) (Database, error) {
	return NewGormDatabase(cfg)
}
```

**Verification**:
```powershell
go build ./internal/database
```

---

### Task 2: Create Domain Models with GORM Tags

#### 2.1 Create `internal/models/user.go`
```go
package models

import (
	"time"
)

type User struct {
	ID                   int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	Username             string     `gorm:"unique;not null;size:50" json:"username"`
	Email                string     `gorm:"unique;not null;size:255" json:"email"`
	PasswordHash         string     `gorm:"not null;size:255" json:"-"`
	FirstName            *string    `gorm:"size:100" json:"first_name,omitempty"`
	LastName             *string    `gorm:"size:100" json:"last_name,omitempty"`
	Phone                *string    `gorm:"size:20" json:"phone,omitempty"`
	IsActive             bool       `gorm:"default:true" json:"is_active"`
	IsEmailVerified      bool       `gorm:"default:false" json:"is_email_verified"`
	EmailVerifiedAt      *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt          *time.Time `json:"last_login_at,omitempty"`
	PasswordChangedAt    *time.Time `json:"password_changed_at,omitempty"`
	FailedLoginAttempts  int        `gorm:"default:0" json:"-"`
	LockedUntil          *time.Time `json:"locked_until,omitempty"`
	CreatedAt            time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt            time.Time  `gorm:"autoUpdateTime" json:"updated_at"`

	// Relationships
	Roles         []Role         `gorm:"many2many:user_roles;" json:"roles,omitempty"`
	RefreshTokens []RefreshToken `gorm:"foreignKey:UserID" json:"-"`
	AuditLogs     []AuditLog     `gorm:"foreignKey:UserID" json:"-"`
}

func (User) TableName() string {
	return "users"
}

// IsAccountLocked checks if the account is currently locked
func (u *User) IsAccountLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

// CanAttemptLogin checks if user can attempt login
func (u *User) CanAttemptLogin() bool {
	return u.IsActive && !u.IsAccountLocked()
}
```

#### 2.2 Create `internal/models/role.go`
```go
package models

import "time"

type Role struct {
	ID          int64       `gorm:"primaryKey;autoIncrement" json:"id"`
	Name        string      `gorm:"unique;not null;size:50" json:"name"`
	Description *string     `gorm:"size:255" json:"description,omitempty"`
	IsActive    bool        `gorm:"default:true" json:"is_active"`
	CreatedAt   time.Time   `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time   `gorm:"autoUpdateTime" json:"updated_at"`

	// Relationships
	Users       []User       `gorm:"many2many:user_roles;" json:"-"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
}

func (Role) TableName() string {
	return "roles"
}

type UserRole struct {
	ID         int64     `gorm:"primaryKey;autoIncrement"`
	UserID     int64     `gorm:"not null"`
	RoleID     int64     `gorm:"not null"`
	AssignedAt time.Time `gorm:"autoCreateTime"`
	AssignedBy *int64

	User User `gorm:"foreignKey:UserID"`
	Role Role `gorm:"foreignKey:RoleID"`
}

func (UserRole) TableName() string {
	return "user_roles"
}
```

#### 2.3 Create `internal/models/permission.go`
```go
package models

import "time"

type Permission struct {
	ID          int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	Name        string    `gorm:"unique;not null;size:100" json:"name"`
	Resource    string    `gorm:"not null;size:50" json:"resource"`
	Action      string    `gorm:"not null;size:50" json:"action"`
	Description *string   `gorm:"size:255" json:"description,omitempty"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`

	// Relationships
	Roles []Role `gorm:"many2many:role_permissions;" json:"-"`
}

func (Permission) TableName() string {
	return "permissions"
}

type RolePermission struct {
	ID           int64     `gorm:"primaryKey;autoIncrement"`
	RoleID       int64     `gorm:"not null"`
	PermissionID int64     `gorm:"not null"`
	AssignedAt   time.Time `gorm:"autoCreateTime"`

	Role       Role       `gorm:"foreignKey:RoleID"`
	Permission Permission `gorm:"foreignKey:PermissionID"`
}

func (RolePermission) TableName() string {
	return "role_permissions"
}
```

#### 2.4 Create `internal/models/refresh_token.go`
```go
package models

import "time"

type RefreshToken struct {
	ID        int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    int64      `gorm:"not null;index" json:"user_id"`
	Token     string     `gorm:"unique;not null;size:500" json:"token"`
	ExpiresAt time.Time  `gorm:"not null;index" json:"expires_at"`
	IsRevoked bool       `gorm:"default:false" json:"is_revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	IPAddress *string    `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent *string    `gorm:"size:500" json:"user_agent,omitempty"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`

	// Relationships
	User User `gorm:"foreignKey:UserID"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// IsValid checks if the refresh token is valid
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsRevoked && time.Now().Before(rt.ExpiresAt)
}
```

#### 2.5 Create `internal/models/audit_log.go`
```go
package models

import "time"

type AuditLog struct {
	ID           int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID       *int64    `gorm:"index" json:"user_id,omitempty"`
	Action       string    `gorm:"not null;size:100;index" json:"action"`
	ResourceType string    `gorm:"not null;size:50;index" json:"resource_type"`
	ResourceID   *int64    `gorm:"index" json:"resource_id,omitempty"`
	OldValues    *string   `gorm:"type:text" json:"old_values,omitempty"`
	NewValues    *string   `gorm:"type:text" json:"new_values,omitempty"`
	IPAddress    *string   `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent    *string   `gorm:"size:500" json:"user_agent,omitempty"`
	Status       string    `gorm:"not null;size:20" json:"status"`
	ErrorMessage *string   `gorm:"type:text" json:"error_message,omitempty"`
	CreatedAt    time.Time `gorm:"autoCreateTime;index" json:"created_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
```

#### 2.6 Create `internal/models/dto.go`
```go
package models

// Auth DTOs

type RegisterRequest struct {
	Username  string  `json:"username" validate:"required,min=3,max=50"`
	Email     string  `json:"email" validate:"required,email"`
	Password  string  `json:"password" validate:"required,min=8"`
	FirstName *string `json:"first_name,omitempty" validate:"omitempty,max=100"`
	LastName  *string `json:"last_name,omitempty" validate:"omitempty,max=100"`
	Phone     *string `json:"phone,omitempty" validate:"omitempty,max=20"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	User         *User  `json:"user,omitempty"`
}

type UserResponse struct {
	User        *User    `json:"user"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}
```

**Verification**:
```powershell
dir internal\models\*.go
go build ./internal/models
```

---

### Task 3: Create Password & JWT Utilities

#### 3.1 Create `pkg/security/password.go`
```go
package security

import (
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLength = 8
	BcryptCost        = 10
)

var (
	ErrPasswordTooShort    = errors.New("password must be at least 8 characters long")
	ErrPasswordNoUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoNumber    = errors.New("password must contain at least one number")
	ErrPasswordNoSpecial   = errors.New("password must contain at least one special character")
)

// HashPassword generates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPasswordHash compares a password with a hash
func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ValidatePasswordStrength checks if password meets security requirements
func ValidatePasswordStrength(password string) error {
	if len(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return ErrPasswordNoUppercase
	}
	if !hasLower {
		return ErrPasswordNoLowercase
	}
	if !hasNumber {
		return ErrPasswordNoNumber
	}
	if !hasSpecial {
		return ErrPasswordNoSpecial
	}

	return nil
}
```

#### 3.2 Create `pkg/jwt/jwt.go`
```go
package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrInvalidSignature = errors.New("invalid token signature")
)

type Claims struct {
	UserID      int64    `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	secretKey          []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

// NewTokenManager creates a new JWT token manager
func NewTokenManager(secretKey string, accessExpiry, refreshExpiry time.Duration) *TokenManager {
	return &TokenManager{
		secretKey:          []byte(secretKey),
		accessTokenExpiry:  accessExpiry,
		refreshTokenExpiry: refreshExpiry,
	}
}

// GenerateAccessToken creates a new access token
func (tm *TokenManager) GenerateAccessToken(userID int64, username, email string, roles, permissions []string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:      userID,
		Username:    username,
		Email:       email,
		Roles:       roles,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(tm.accessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tm.secretKey)
}

// GenerateRefreshToken creates a new refresh token
func (tm *TokenManager) GenerateRefreshToken(userID int64, username string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(now.Add(tm.refreshTokenExpiry)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Subject:   username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tm.secretKey)
}

// ValidateToken validates and parses a JWT token
func (tm *TokenManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSignature
		}
		return tm.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// GetAccessTokenExpiry returns the access token expiry duration
func (tm *TokenManager) GetAccessTokenExpiry() time.Duration {
	return tm.accessTokenExpiry
}

// GetRefreshTokenExpiry returns the refresh token expiry duration
func (tm *TokenManager) GetRefreshTokenExpiry() time.Duration {
	return tm.refreshTokenExpiry
}
```

**Verification**:
```powershell
go build ./pkg/security
go build ./pkg/jwt
```

---

### Task 4: Create Repository Layer with GORM

#### 4.1 Create `internal/repository/user_repository.go`
```go
package repository

import (
	"errors"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"gorm.io/gorm"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(user *models.User) error {
	result := r.db.Create(user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
			return ErrUserAlreadyExists
		}
		return result.Error
	}
	return nil
}

// FindByUsername finds a user by username
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

// FindByEmail finds a user by email
func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	result := r.db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

// FindByID finds a user by ID
func (r *UserRepository) FindByID(id int64) (*models.User, error) {
	var user models.User
	result := r.db.First(&user, id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

// FindByIDWithRoles finds user with preloaded roles and permissions
func (r *UserRepository) FindByIDWithRoles(id int64) (*models.User, error) {
	var user models.User
	result := r.db.Preload("Roles.Permissions").First(&user, id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

// UpdateLastLogin updates the last login timestamp
func (r *UserRepository) UpdateLastLogin(userID int64) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"last_login_at":          time.Now(),
		"failed_login_attempts":  0,
		"locked_until":           nil,
	}).Error
}

// IncrementFailedLoginAttempts increments failed login counter
func (r *UserRepository) IncrementFailedLoginAttempts(userID int64) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).
		UpdateColumn("failed_login_attempts", gorm.Expr("failed_login_attempts + ?", 1)).Error
}

// LockAccount locks the user account until specified time
func (r *UserRepository) LockAccount(userID int64, until time.Time) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"locked_until": until,
	}).Error
}

// AssignRole assigns a role to a user
func (r *UserRepository) AssignRole(userID, roleID int64, assignedBy *int64) error {
	userRole := models.UserRole{
		UserID:     userID,
		RoleID:     roleID,
		AssignedBy: assignedBy,
	}
	return r.db.Create(&userRole).Error
}
```

#### 4.2 Create `internal/repository/auth_repository.go`
```go
package repository

import (
	"errors"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"gorm.io/gorm"
)

var (
	ErrTokenNotFound = errors.New("token not found")
)

type AuthRepository struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

// SaveRefreshToken saves a refresh token to database
func (r *AuthRepository) SaveRefreshToken(token *models.RefreshToken) error {
	return r.db.Create(token).Error
}

// FindRefreshToken finds a refresh token by token string
func (r *AuthRepository) FindRefreshToken(tokenString string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	result := r.db.Where("token = ?", tokenString).First(&token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &token, nil
}

// RevokeRefreshToken revokes a refresh token
func (r *AuthRepository) RevokeRefreshToken(tokenString string) error {
	now := time.Now()
	return r.db.Model(&models.RefreshToken{}).
		Where("token = ?", tokenString).
		Updates(map[string]interface{}{
			"is_revoked": true,
			"revoked_at": now,
		}).Error
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (r *AuthRepository) RevokeAllUserTokens(userID int64) error {
	now := time.Now()
	return r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND is_revoked = ?", userID, false).
		Updates(map[string]interface{}{
			"is_revoked": true,
			"revoked_at": now,
		}).Error
}

// DeleteExpiredTokens deletes all expired refresh tokens
func (r *AuthRepository) DeleteExpiredTokens() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error
}
```

#### 4.3 Create `internal/repository/role_repository.go`
```go
package repository

import (
	"gorm.io/gorm"
)

type RoleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// GetUserRoles returns all role names for a user
func (r *RoleRepository) GetUserRoles(userID int64) ([]string, error) {
	var roles []string
	err := r.db.Table("roles").
		Select("roles.name").
		Joins("INNER JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ? AND roles.is_active = ?", userID, true).
		Pluck("name", &roles).Error
	
	return roles, err
}

// GetUserPermissions returns all permission names for a user
func (r *RoleRepository) GetUserPermissions(userID int64) ([]string, error) {
	var permissions []string
	err := r.db.Table("permissions").
		Select("DISTINCT permissions.name").
		Joins("INNER JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("INNER JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Pluck("name", &permissions).Error
	
	return permissions, err
}

// GetRoleIDByName returns the role ID by name
func (r *RoleRepository) GetRoleIDByName(name string) (int64, error) {
	var roleID int64
	err := r.db.Table("roles").Select("id").Where("name = ?", name).Scan(&roleID).Error
	return roleID, err
}

// HasPermission checks if a user has a specific permission
func (r *RoleRepository) HasPermission(userID int64, permissionName string) (bool, error) {
	var count int64
	err := r.db.Table("permissions").
		Joins("INNER JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("INNER JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ? AND permissions.name = ?", userID, permissionName).
		Count(&count).Error
	
	return count > 0, err
}
```

#### 4.4 Create `internal/repository/audit_repository.go`
```go
package repository

import (
	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"gorm.io/gorm"
)

type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Log creates an audit log entry
func (r *AuditRepository) Log(log *models.AuditLog) error {
	return r.db.Create(log).Error
}
```

**Verification**:
```powershell
go build ./internal/repository
```

---

### Task 5: Create Service Layer

#### 5.1 Create `internal/services/auth_service.go`
```go
package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"github.com/HashanEranga/go-task-manager-service/internal/repository"
	"github.com/HashanEranga/go-task-manager-service/pkg/jwt"
	"github.com/HashanEranga/go-task-manager-service/pkg/logger"
	"github.com/HashanEranga/go-task-manager-service/pkg/security"
)

const (
	MaxFailedLoginAttempts = 5
	AccountLockDuration    = 15 * time.Minute
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is locked due to too many failed login attempts")
	ErrAccountInactive    = errors.New("account is inactive")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

type AuthService struct {
	userRepo  *repository.UserRepository
	authRepo  *repository.AuthRepository
	roleRepo  *repository.RoleRepository
	auditRepo *repository.AuditRepository
	tokenMgr  *jwt.TokenManager
}

func NewAuthService(
	userRepo *repository.UserRepository,
	authRepo *repository.AuthRepository,
	roleRepo *repository.RoleRepository,
	auditRepo *repository.AuditRepository,
	tokenMgr *jwt.TokenManager,
) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		authRepo:  authRepo,
		roleRepo:  roleRepo,
		auditRepo: auditRepo,
		tokenMgr:  tokenMgr,
	}
}

// Register registers a new user
func (s *AuthService) Register(req *models.RegisterRequest, ipAddress, userAgent string) (*models.AuthResponse, error) {
	// Validate password strength
	if err := security.ValidatePasswordStrength(req.Password); err != nil {
		s.logAudit(nil, "user.register", "users", nil, "failure", err.Error(), ipAddress, userAgent)
		return nil, err
	}

	// Check if username exists
	if _, err := s.userRepo.FindByUsername(req.Username); err == nil {
		return nil, errors.New("username already exists")
	}

	// Check if email exists
	if _, err := s.userRepo.FindByEmail(req.Email); err == nil {
		return nil, errors.New("email already exists")
	}

	// Hash password
	passwordHash, err := security.HashPassword(req.Password)
	if err != nil {
		logger.Error("Failed to hash password", err)
		return nil, errors.New("failed to process password")
	}

	// Create user
	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Phone:        req.Phone,
		IsActive:     true,
	}

	if err := s.userRepo.Create(user); err != nil {
		s.logAudit(nil, "user.register", "users", nil, "failure", err.Error(), ipAddress, userAgent)
		return nil, err
	}

	// Assign default USER role
	roleID, err := s.roleRepo.GetRoleIDByName("USER")
	if err == nil {
		s.userRepo.AssignRole(user.ID, roleID, nil)
	}

	// Log success
	s.logAudit(&user.ID, "user.register", "users", &user.ID, "success", "", ipAddress, userAgent)

	// Generate tokens
	return s.generateTokens(user, ipAddress, userAgent)
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(req *models.LoginRequest, ipAddress, userAgent string) (*models.AuthResponse, error) {
	// Find user
	user, err := s.userRepo.FindByUsername(req.Username)
	if err != nil {
		s.logAudit(nil, "user.login", "users", nil, "failure", "user not found", ipAddress, userAgent)
		return nil, ErrInvalidCredentials
	}

	// Check if account is locked
	if user.IsAccountLocked() {
		s.logAudit(&user.ID, "user.login", "users", &user.ID, "failure", "account locked", ipAddress, userAgent)
		return nil, ErrAccountLocked
	}

	// Check if account is active
	if !user.IsActive {
		s.logAudit(&user.ID, "user.login", "users", &user.ID, "failure", "account inactive", ipAddress, userAgent)
		return nil, ErrAccountInactive
	}

	// Verify password
	if err := security.CheckPasswordHash(req.Password, user.PasswordHash); err != nil {
		// Increment failed attempts
		s.userRepo.IncrementFailedLoginAttempts(user.ID)

		// Lock account if max attempts reached
		if user.FailedLoginAttempts+1 >= MaxFailedLoginAttempts {
			lockUntil := time.Now().Add(AccountLockDuration)
			s.userRepo.LockAccount(user.ID, lockUntil)
			s.logAudit(&user.ID, "user.login", "users", &user.ID, "failure", "account locked after max attempts", ipAddress, userAgent)
			return nil, ErrAccountLocked
		}

		s.logAudit(&user.ID, "user.login", "users", &user.ID, "failure", "invalid password", ipAddress, userAgent)
		return nil, ErrInvalidCredentials
	}

	// Update last login and reset failed attempts
	s.userRepo.UpdateLastLogin(user.ID)

	// Log success
	s.logAudit(&user.ID, "user.login", "users", &user.ID, "success", "", ipAddress, userAgent)

	// Generate tokens
	return s.generateTokens(user, ipAddress, userAgent)
}

// RefreshToken generates new access token from refresh token
func (s *AuthService) RefreshToken(refreshTokenStr string, ipAddress, userAgent string) (*models.AuthResponse, error) {
	// Find refresh token
	token, err := s.authRepo.FindRefreshToken(refreshTokenStr)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Validate token
	if !token.IsValid() {
		return nil, ErrInvalidToken
	}

	// Get user
	user, err := s.userRepo.FindByID(token.UserID)
	if err != nil {
		return nil, err
	}

	// Check if user is still active
	if !user.CanAttemptLogin() {
		return nil, ErrAccountInactive
	}

	// Revoke old token
	s.authRepo.RevokeRefreshToken(refreshTokenStr)

	// Generate new tokens
	return s.generateTokens(user, ipAddress, userAgent)
}

// Logout revokes the refresh token
func (s *AuthService) Logout(refreshTokenStr string, userID int64) error {
	if refreshTokenStr != "" {
		s.authRepo.RevokeRefreshToken(refreshTokenStr)
	}
	return nil
}

// GetUserProfile returns user with roles and permissions
func (s *AuthService) GetUserProfile(userID int64) (*models.UserResponse, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, err
	}

	roles, _ := s.roleRepo.GetUserRoles(userID)
	permissions, _ := s.roleRepo.GetUserPermissions(userID)

	return &models.UserResponse{
		User:        user,
		Roles:       roles,
		Permissions: permissions,
	}, nil
}

// generateTokens generates access and refresh tokens
func (s *AuthService) generateTokens(user *models.User, ipAddress, userAgent string) (*models.AuthResponse, error) {
	// Get user roles and permissions
	roles, _ := s.roleRepo.GetUserRoles(user.ID)
	permissions, _ := s.roleRepo.GetUserPermissions(user.ID)

	// Generate access token
	accessToken, err := s.tokenMgr.GenerateAccessToken(
		user.ID,
		user.Username,
		user.Email,
		roles,
		permissions,
	)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := s.tokenMgr.GenerateRefreshToken(user.ID, user.Username)
	if err != nil {
		return nil, err
	}

	// Save refresh token to database
	ip := &ipAddress
	ua := &userAgent
	refreshTokenModel := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.tokenMgr.GetRefreshTokenExpiry()),
		IPAddress: ip,
		UserAgent: ua,
	}

	if err := s.authRepo.SaveRefreshToken(refreshTokenModel); err != nil {
		logger.Error("Failed to save refresh token", err)
	}

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.tokenMgr.GetAccessTokenExpiry().Seconds()),
		User:         user,
	}, nil
}

// logAudit creates an audit log entry
func (s *AuthService) logAudit(userID *int64, action, resourceType string, resourceID *int64, status, errorMsg, ipAddress, userAgent string) {
	ip := &ipAddress
	ua := &userAgent
	var errMsg *string
	if errorMsg != "" {
		errMsg = &errorMsg
	}

	log := &models.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Status:       status,
		ErrorMessage: errMsg,
		IPAddress:    ip,
		UserAgent:    ua,
	}

	if err := s.auditRepo.Log(log); err != nil {
		logger.Error(fmt.Sprintf("Failed to create audit log for action %s", action), err)
	}
}
```

#### 5.2 Create `internal/services/user_service.go`
```go
package services

import (
	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"github.com/HashanEranga/go-task-manager-service/internal/repository"
)

type UserService struct {
	userRepo *repository.UserRepository
	roleRepo *repository.RoleRepository
}

func NewUserService(userRepo *repository.UserRepository, roleRepo *repository.RoleRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
		roleRepo: roleRepo,
	}
}

// GetByID gets a user by ID
func (s *UserService) GetByID(id int64) (*models.User, error) {
	return s.userRepo.FindByID(id)
}

// GetUserWithRoles gets user with their roles and permissions
func (s *UserService) GetUserWithRoles(id int64) (*models.UserResponse, error) {
	user, err := s.userRepo.FindByIDWithRoles(id)
	if err != nil {
		return nil, err
	}

	roles, _ := s.roleRepo.GetUserRoles(id)
	permissions, _ := s.roleRepo.GetUserPermissions(id)

	return &models.UserResponse{
		User:        user,
		Roles:       roles,
		Permissions: permissions,
	}, nil
}
```

**Verification**:
```powershell
go build ./internal/services
```

---

### Task 6: Create Handlers & Middleware

#### 6.1 Create `internal/handlers/auth_handler.go`
(Same as raw SQL version - no changes needed)

```go
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"github.com/HashanEranga/go-task-manager-service/internal/services"
	"github.com/HashanEranga/go-task-manager-service/pkg/logger"
	"github.com/HashanEranga/go-task-manager-service/pkg/response"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	authResp, err := h.authService.Register(&req, ipAddress, userAgent)
	if err != nil {
		logger.Error("Registration failed", err)
		response.Error(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	response.JSON(w, http.StatusCreated, authResp)
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	authResp, err := h.authService.Login(&req, ipAddress, userAgent)
	if err != nil {
		logger.Error("Login failed", err)
		
		if err == services.ErrInvalidCredentials {
			response.Error(w, http.StatusUnauthorized, "Invalid credentials", err)
			return
		}
		if err == services.ErrAccountLocked {
			response.Error(w, http.StatusForbidden, "Account is locked", err)
			return
		}
		if err == services.ErrAccountInactive {
			response.Error(w, http.StatusForbidden, "Account is inactive", err)
			return
		}
		
		response.Error(w, http.StatusInternalServerError, "Login failed", err)
		return
	}

	response.JSON(w, http.StatusOK, authResp)
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	authResp, err := h.authService.RefreshToken(req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "Invalid or expired token", err)
		return
	}

	response.JSON(w, http.StatusOK, authResp)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(int64)
	if !ok {
		response.Error(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	var req models.RefreshTokenRequest
	json.NewDecoder(r.Body).Decode(&req)

	h.authService.Logout(req.RefreshToken, userID)

	response.JSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// Me returns current user profile
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(int64)
	if !ok {
		response.Error(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	userProfile, err := h.authService.GetUserProfile(userID)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Failed to get user profile", err)
		return
	}

	response.JSON(w, http.StatusOK, userProfile)
}

func getIPAddress(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
```

#### 6.2 Create Middleware
(Same as raw SQL version - copy from PHASE_3_AUTH_IMPLEMENTATION.md Task 7)

**Verification**:
```powershell
go build ./internal/handlers
go build ./internal/middleware
```

---

### Task 7: Wire Up Router in Main

#### 7.1 Update `cmd/server/main.go`

Replace the database connection section (after line 33):

```go
// Create GORM database connection
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

// Get GORM DB instance
gormDB := db.GetGormDB()

// Initialize JWT Token Manager
tokenManager := jwt.NewTokenManager(
	cfg.JWT.Secret,
	cfg.JWT.Expiry,
	cfg.JWT.RefreshExpiry,
)

// Initialize repositories with GORM
userRepo := repository.NewUserRepository(gormDB)
authRepo := repository.NewAuthRepository(gormDB)
roleRepo := repository.NewRoleRepository(gormDB)
auditRepo := repository.NewAuditRepository(gormDB)

// Initialize services
authService := services.NewAuthService(userRepo, authRepo, roleRepo, auditRepo, tokenManager)
userService := services.NewUserService(userRepo, roleRepo)

// Initialize handlers
authHandler := handlers.NewAuthHandler(authService)

// Initialize middleware
authMiddleware := middleware.NewAuthMiddleware(tokenManager)
```

Update imports:
```go
import (
	"context"
	"errors"
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
	appmiddleware "github.com/HashanEranga/go-task-manager-service/internal/middleware"
	"github.com/HashanEranga/go-task-manager-service/internal/repository"
	"github.com/HashanEranga/go-task-manager-service/internal/services"
	"github.com/HashanEranga/go-task-manager-service/pkg/jwt"
	"github.com/HashanEranga/go-task-manager-service/pkg/logger"
)
```

Update router (around line 74):
```go
r.Route("/api", func(r chi.Router) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("TaskFlow API v1.0 with GORM"))
	})

	// Public auth routes
	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", authHandler.RefreshToken)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(appmiddleware.Authenticate)
			r.Get("/me", authHandler.Me)
			r.Post("/logout", authHandler.Logout)
		})
	})
})
```

**Verification**:
```powershell
go build -o bin/taskflow.exe cmd/server/main.go
```

---

### Task 8: Test Authentication Flow

#### 8.1 Start server
```powershell
go run cmd/server/main.go
```

#### 8.2 Test Registration
```powershell
$body = @{
    username = "gormuser"
    email = "gorm@example.com"
    password = "Gorm@123456"
    first_name = "GORM"
    last_name = "User"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/register" -Method Post -Body $body -ContentType "application/json"
$response | ConvertTo-Json -Depth 10
```

#### 8.3 Test Login
```powershell
$loginBody = @{
    username = "gormuser"
    password = "Gorm@123456"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json"

$accessToken = $response.access_token
$refreshToken = $response.refresh_token

Write-Host "Access Token: $accessToken"
```

#### 8.4 Test Protected Endpoint
```powershell
$headers = @{
    "Authorization" = "Bearer $accessToken"
}

Invoke-RestMethod -Uri "http://localhost:8080/api/auth/me" -Method Get -Headers $headers | ConvertTo-Json -Depth 10
```

#### 8.5 Test Token Refresh
```powershell
$refreshBody = @{
    refresh_token = $refreshToken
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/auth/refresh" -Method Post -Body $refreshBody -ContentType "application/json" | ConvertTo-Json
```

#### 8.6 Verify in Database
```sql
-- Check GORM created user
SELECT * FROM users WHERE username = 'gormuser';

-- Check roles assigned
SELECT u.username, r.name 
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'gormuser';

-- Check audit logs
SELECT * FROM audit_logs 
WHERE action LIKE 'user.%'
ORDER BY created_at DESC 
LIMIT 10;
```

---

## Success Checklist

- [ ] GORM dependencies installed
- [ ] GORM database connection working
- [ ] Models with GORM tags created
- [ ] Repositories use GORM methods (Create, Where, First, etc.)
- [ ] Services layer complete
- [ ] Handlers working
- [ ] Middleware validates tokens
- [ ] Main.go wired with GORM
- [ ] User can register
- [ ] User can login
- [ ] Protected endpoints require token
- [ ] Token refresh works
- [ ] Audit logs created
- [ ] Works with PostgreSQL
- [ ] Works with SQL Server

---

## GORM vs Raw SQL Comparison

### Code Reduction

**Raw SQL (user_repository.go):**
- ~700 lines
- Manual query building
- Manual scanning
- Separate queries for PostgreSQL/MSSQL

**GORM (user_repository.go):**
- ~180 lines (74% less code!)
- Auto query building
- Auto scanning
- Works with both databases automatically

### Example Comparison

**Finding user with roles (Raw SQL):**
```go
// 50+ lines of code with joins and scanning
```

**Finding user with roles (GORM):**
```go
db.Preload("Roles.Permissions").First(&user, id)
```

**One line!** 🎉

---

## Troubleshooting

### GORM Connection Error
```powershell
# Check GORM is installed
go list -m gorm.io/gorm

# Reinstall if needed
go get -u gorm.io/gorm
go mod tidy
```

### Duplicate Key Error
```
Error: duplicate key value
```
GORM automatically handles this - check your Create() error handling.

### Preload Not Working
```go
// Wrong
db.First(&user, id)

// Correct - use Preload
db.Preload("Roles.Permissions").First(&user, id)
```

---

## Next Steps

Once Phase 3 with GORM is complete:
1. **Phase 4**: User Management CRUD (even simpler with GORM!)
2. **Phase 5**: Projects Module
3. **Phase 6**: Tasks Module
4. **Phase 7**: Collaboration Features
5. **Phase 8**: Testing & Deployment

---

## Benefits You'll Experience

✅ **80% less repository code**
✅ **Auto database dialect handling**
✅ **Type-safe queries**
✅ **Easy relationship loading**
✅ **Built-in pagination**
✅ **Query builder chainable methods**
✅ **Auto timestamps**
✅ **Migration support (optional)**

---

**Phase 3 with GORM Status**: Ready for Implementation
**Estimated Time**: 4-5 hours (vs 6-8 with raw SQL)
**Difficulty**: Easy-Moderate (GORM abstracts complexity)
**Recommendation**: ⭐⭐⭐⭐⭐ Highly recommended for faster development!
