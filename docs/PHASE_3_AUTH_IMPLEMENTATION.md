# Phase 3: Authentication & Authorization Implementation Guide

## Overview
This guide provides step-by-step instructions to implement the authentication and authorization layer for TaskFlow. Follow each task in order.

## Prerequisites
- ✅ Database setup complete (PostgreSQL or SQL Server)
- ✅ Go application structure ready
- ✅ Dependencies installed (`go mod tidy`)

## Implementation Checklist

### Task 1: Create Domain Models
**Location**: `internal/models/`

Create the following files:

#### 1.1 Create `internal/models/user.go`
```go
package models

import (
	"time"
)

type User struct {
	ID                   int64      `json:"id" db:"id"`
	Username             string     `json:"username" db:"username"`
	Email                string     `json:"email" db:"email"`
	PasswordHash         string     `json:"-" db:"password_hash"`
	FirstName            *string    `json:"first_name,omitempty" db:"first_name"`
	LastName             *string    `json:"last_name,omitempty" db:"last_name"`
	Phone                *string    `json:"phone,omitempty" db:"phone"`
	IsActive             bool       `json:"is_active" db:"is_active"`
	IsEmailVerified      bool       `json:"is_email_verified" db:"is_email_verified"`
	EmailVerifiedAt      *time.Time `json:"email_verified_at,omitempty" db:"email_verified_at"`
	LastLoginAt          *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	PasswordChangedAt    *time.Time `json:"password_changed_at,omitempty" db:"password_changed_at"`
	FailedLoginAttempts  int        `json:"-" db:"failed_login_attempts"`
	LockedUntil          *time.Time `json:"locked_until,omitempty" db:"locked_until"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
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

#### 1.2 Create `internal/models/role.go`
```go
package models

import "time"

type Role struct {
	ID          int64     `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description *string   `json:"description,omitempty" db:"description"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type UserRole struct {
	ID         int64     `json:"id" db:"id"`
	UserID     int64     `json:"user_id" db:"user_id"`
	RoleID     int64     `json:"role_id" db:"role_id"`
	AssignedAt time.Time `json:"assigned_at" db:"assigned_at"`
	AssignedBy *int64    `json:"assigned_by,omitempty" db:"assigned_by"`
}
```

#### 1.3 Create `internal/models/permission.go`
```go
package models

import "time"

type Permission struct {
	ID          int64     `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Resource    string    `json:"resource" db:"resource"`
	Action      string    `json:"action" db:"action"`
	Description *string   `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type RolePermission struct {
	ID           int64     `json:"id" db:"id"`
	RoleID       int64     `json:"role_id" db:"role_id"`
	PermissionID int64     `json:"permission_id" db:"permission_id"`
	AssignedAt   time.Time `json:"assigned_at" db:"assigned_at"`
}
```

#### 1.4 Create `internal/models/refresh_token.go`
```go
package models

import "time"

type RefreshToken struct {
	ID         int64      `json:"id" db:"id"`
	UserID     int64      `json:"user_id" db:"user_id"`
	Token      string     `json:"token" db:"token"`
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	IsRevoked  bool       `json:"is_revoked" db:"is_revoked"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	IPAddress  *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  *string    `json:"user_agent,omitempty" db:"user_agent"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// IsValid checks if the refresh token is valid
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsRevoked && time.Now().Before(rt.ExpiresAt)
}
```

#### 1.5 Create `internal/models/audit_log.go`
```go
package models

import "time"

type AuditLog struct {
	ID           int64      `json:"id" db:"id"`
	UserID       *int64     `json:"user_id,omitempty" db:"user_id"`
	Action       string     `json:"action" db:"action"`
	ResourceType string     `json:"resource_type" db:"resource_type"`
	ResourceID   *int64     `json:"resource_id,omitempty" db:"resource_id"`
	OldValues    *string    `json:"old_values,omitempty" db:"old_values"`
	NewValues    *string    `json:"new_values,omitempty" db:"new_values"`
	IPAddress    *string    `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent    *string    `json:"user_agent,omitempty" db:"user_agent"`
	Status       string     `json:"status" db:"status"`
	ErrorMessage *string    `json:"error_message,omitempty" db:"error_message"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}
```

#### 1.6 Create `internal/models/dto.go`
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
# Check all model files are created
dir internal\models\*.go
```

---

### Task 2: Create Password Utilities
**Location**: `pkg/security/`

#### 2.1 Create `pkg/security/password.go`
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
	ErrPasswordMismatch    = errors.New("password does not match")
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

**Verification**:
```powershell
# Test password utilities
go test ./pkg/security -v
```

---

### Task 3: Create JWT Utilities
**Location**: `pkg/jwt/`

#### 3.1 Install JWT dependency
```powershell
go get github.com/golang-jwt/jwt/v5
go mod tidy
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
	secretKey           []byte
	accessTokenExpiry   time.Duration
	refreshTokenExpiry  time.Duration
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
		ID:        string(rune(userID)), // Token ID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tm.secretKey)
}

// ValidateToken validates and parses a JWT token
func (tm *TokenManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
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
# Build to check for syntax errors
go build ./pkg/jwt
```

---

### Task 4: Create Repository Layer
**Location**: `internal/repository/`

#### 4.1 Create `internal/repository/user_repository.go`
```go
package repository

import (
	"database/sql"
	"errors"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/database"
	"github.com/HashanEranga/go-task-manager-service/internal/models"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

type UserRepository struct {
	db database.Database
}

func NewUserRepository(db database.Database) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(user *models.User) error {
	query := `
		INSERT INTO users (username, email, password_hash, first_name, last_name, phone, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`

	// Handle SQL Server vs PostgreSQL differences
	if r.db.GetDriverName() == "mssql" {
		query = `
			INSERT INTO users (username, email, password_hash, first_name, last_name, phone, is_active, created_at, updated_at)
			OUTPUT INSERTED.id
			VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9)
		`
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	user.IsActive = true

	err := r.db.GetDB().QueryRow(
		query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.Phone,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	).Scan(&user.ID)

	if err != nil {
		// Check for unique constraint violation
		if err.Error() == "pq: duplicate key value violates unique constraint" ||
			err.Error() == "mssql: Violation of UNIQUE KEY constraint" {
			return ErrUserAlreadyExists
		}
		return err
	}

	return nil
}

// FindByUsername finds a user by username
func (r *UserRepository) FindByUsername(username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, phone, 
		       is_active, is_email_verified, email_verified_at, last_login_at, 
		       password_changed_at, failed_login_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE username = $1
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			SELECT id, username, email, password_hash, first_name, last_name, phone, 
			       is_active, is_email_verified, email_verified_at, last_login_at, 
			       password_changed_at, failed_login_attempts, locked_until, created_at, updated_at
			FROM users
			WHERE username = @p1
		`
	}

	user := &models.User{}
	err := r.db.GetDB().QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.Phone,
		&user.IsActive,
		&user.IsEmailVerified,
		&user.EmailVerifiedAt,
		&user.LastLoginAt,
		&user.PasswordChangedAt,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// FindByEmail finds a user by email
func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, phone, 
		       is_active, is_email_verified, email_verified_at, last_login_at, 
		       password_changed_at, failed_login_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			SELECT id, username, email, password_hash, first_name, last_name, phone, 
			       is_active, is_email_verified, email_verified_at, last_login_at, 
			       password_changed_at, failed_login_attempts, locked_until, created_at, updated_at
			FROM users
			WHERE email = @p1
		`
	}

	user := &models.User{}
	err := r.db.GetDB().QueryRow(query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.Phone,
		&user.IsActive,
		&user.IsEmailVerified,
		&user.EmailVerifiedAt,
		&user.LastLoginAt,
		&user.PasswordChangedAt,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// FindByID finds a user by ID
func (r *UserRepository) FindByID(id int64) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, phone, 
		       is_active, is_email_verified, email_verified_at, last_login_at, 
		       password_changed_at, failed_login_attempts, locked_until, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			SELECT id, username, email, password_hash, first_name, last_name, phone, 
			       is_active, is_email_verified, email_verified_at, last_login_at, 
			       password_changed_at, failed_login_attempts, locked_until, created_at, updated_at
			FROM users
			WHERE id = @p1
		`
	}

	user := &models.User{}
	err := r.db.GetDB().QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.Phone,
		&user.IsActive,
		&user.IsEmailVerified,
		&user.EmailVerifiedAt,
		&user.LastLoginAt,
		&user.PasswordChangedAt,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// UpdateLastLogin updates the last login timestamp
func (r *UserRepository) UpdateLastLogin(userID int64) error {
	query := `UPDATE users SET last_login_at = $1, failed_login_attempts = 0, locked_until = NULL WHERE id = $2`

	if r.db.GetDriverName() == "mssql" {
		query = `UPDATE users SET last_login_at = @p1, failed_login_attempts = 0, locked_until = NULL WHERE id = @p2`
	}

	_, err := r.db.GetDB().Exec(query, time.Now(), userID)
	return err
}

// IncrementFailedLoginAttempts increments failed login counter
func (r *UserRepository) IncrementFailedLoginAttempts(userID int64) error {
	query := `UPDATE users SET failed_login_attempts = failed_login_attempts + 1, updated_at = $1 WHERE id = $2`

	if r.db.GetDriverName() == "mssql" {
		query = `UPDATE users SET failed_login_attempts = failed_login_attempts + 1, updated_at = @p1 WHERE id = @p2`
	}

	_, err := r.db.GetDB().Exec(query, time.Now(), userID)
	return err
}

// LockAccount locks the user account until specified time
func (r *UserRepository) LockAccount(userID int64, until time.Time) error {
	query := `UPDATE users SET locked_until = $1, updated_at = $2 WHERE id = $3`

	if r.db.GetDriverName() == "mssql" {
		query = `UPDATE users SET locked_until = @p1, updated_at = @p2 WHERE id = @p3`
	}

	_, err := r.db.GetDB().Exec(query, until, time.Now(), userID)
	return err
}

// AssignRole assigns a role to a user
func (r *UserRepository) AssignRole(userID, roleID int64, assignedBy *int64) error {
	query := `INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by) VALUES ($1, $2, $3, $4)`

	if r.db.GetDriverName() == "mssql" {
		query = `INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by) VALUES (@p1, @p2, @p3, @p4)`
	}

	_, err := r.db.GetDB().Exec(query, userID, roleID, time.Now(), assignedBy)
	return err
}
```

#### 4.2 Create `internal/repository/auth_repository.go`
```go
package repository

import (
	"database/sql"
	"errors"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/database"
	"github.com/HashanEranga/go-task-manager-service/internal/models"
)

var (
	ErrTokenNotFound = errors.New("token not found")
)

type AuthRepository struct {
	db database.Database
}

func NewAuthRepository(db database.Database) *AuthRepository {
	return &AuthRepository{db: db}
}

// SaveRefreshToken saves a refresh token to database
func (r *AuthRepository) SaveRefreshToken(token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token, expires_at, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			INSERT INTO refresh_tokens (user_id, token, expires_at, ip_address, user_agent, created_at)
			OUTPUT INSERTED.id
			VALUES (@p1, @p2, @p3, @p4, @p5, @p6)
		`
	}

	token.CreatedAt = time.Now()
	token.IsRevoked = false

	err := r.db.GetDB().QueryRow(
		query,
		token.UserID,
		token.Token,
		token.ExpiresAt,
		token.IPAddress,
		token.UserAgent,
		token.CreatedAt,
	).Scan(&token.ID)

	return err
}

// FindRefreshToken finds a refresh token by token string
func (r *AuthRepository) FindRefreshToken(tokenString string) (*models.RefreshToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, is_revoked, revoked_at, 
		       ip_address, user_agent, created_at
		FROM refresh_tokens
		WHERE token = $1
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			SELECT id, user_id, token, expires_at, is_revoked, revoked_at, 
			       ip_address, user_agent, created_at
			FROM refresh_tokens
			WHERE token = @p1
		`
	}

	token := &models.RefreshToken{}
	err := r.db.GetDB().QueryRow(query, tokenString).Scan(
		&token.ID,
		&token.UserID,
		&token.Token,
		&token.ExpiresAt,
		&token.IsRevoked,
		&token.RevokedAt,
		&token.IPAddress,
		&token.UserAgent,
		&token.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	return token, nil
}

// RevokeRefreshToken revokes a refresh token
func (r *AuthRepository) RevokeRefreshToken(tokenString string) error {
	query := `UPDATE refresh_tokens SET is_revoked = true, revoked_at = $1 WHERE token = $2`

	if r.db.GetDriverName() == "mssql" {
		query = `UPDATE refresh_tokens SET is_revoked = 1, revoked_at = @p1 WHERE token = @p2`
	}

	_, err := r.db.GetDB().Exec(query, time.Now(), tokenString)
	return err
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (r *AuthRepository) RevokeAllUserTokens(userID int64) error {
	query := `UPDATE refresh_tokens SET is_revoked = true, revoked_at = $1 WHERE user_id = $2 AND is_revoked = false`

	if r.db.GetDriverName() == "mssql" {
		query = `UPDATE refresh_tokens SET is_revoked = 1, revoked_at = @p1 WHERE user_id = @p2 AND is_revoked = 0`
	}

	_, err := r.db.GetDB().Exec(query, time.Now(), userID)
	return err
}

// DeleteExpiredTokens deletes all expired refresh tokens
func (r *AuthRepository) DeleteExpiredTokens() error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < $1`

	if r.db.GetDriverName() == "mssql" {
		query = `DELETE FROM refresh_tokens WHERE expires_at < @p1`
	}

	_, err := r.db.GetDB().Exec(query, time.Now())
	return err
}
```

#### 4.3 Create `internal/repository/role_repository.go`
```go
package repository

import (
	"github.com/HashanEranga/go-task-manager-service/internal/database"
)

type RoleRepository struct {
	db database.Database
}

func NewRoleRepository(db database.Database) *RoleRepository {
	return &RoleRepository{db: db}
}

// GetUserRoles returns all role names for a user
func (r *RoleRepository) GetUserRoles(userID int64) ([]string, error) {
	query := `
		SELECT r.name
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.is_active = true
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			SELECT r.name
			FROM roles r
			INNER JOIN user_roles ur ON r.id = ur.role_id
			WHERE ur.user_id = @p1 AND r.is_active = 1
		`
	}

	rows, err := r.db.GetDB().Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

// GetUserPermissions returns all permission names for a user
func (r *RoleRepository) GetUserPermissions(userID int64) ([]string, error) {
	query := `
		SELECT DISTINCT p.name
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			SELECT DISTINCT p.name
			FROM permissions p
			INNER JOIN role_permissions rp ON p.id = rp.permission_id
			INNER JOIN user_roles ur ON rp.role_id = ur.role_id
			WHERE ur.user_id = @p1
		`
	}

	rows, err := r.db.GetDB().Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

// GetRoleIDByName returns the role ID by name
func (r *RoleRepository) GetRoleIDByName(name string) (int64, error) {
	query := `SELECT id FROM roles WHERE name = $1`

	if r.db.GetDriverName() == "mssql" {
		query = `SELECT id FROM roles WHERE name = @p1`
	}

	var roleID int64
	err := r.db.GetDB().QueryRow(query, name).Scan(&roleID)
	return roleID, err
}

// HasPermission checks if a user has a specific permission
func (r *RoleRepository) HasPermission(userID int64, permissionName string) (bool, error) {
	query := `
		SELECT COUNT(*)
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1 AND p.name = $2
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			SELECT COUNT(*)
			FROM permissions p
			INNER JOIN role_permissions rp ON p.id = rp.permission_id
			INNER JOIN user_roles ur ON rp.role_id = ur.role_id
			WHERE ur.user_id = @p1 AND p.name = @p2
		`
	}

	var count int
	err := r.db.GetDB().QueryRow(query, userID, permissionName).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
```

#### 4.4 Create `internal/repository/audit_repository.go`
```go
package repository

import (
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/database"
	"github.com/HashanEranga/go-task-manager-service/internal/models"
)

type AuditRepository struct {
	db database.Database
}

func NewAuditRepository(db database.Database) *AuditRepository {
	return &AuditRepository{db: db}
}

// Log creates an audit log entry
func (r *AuditRepository) Log(log *models.AuditLog) error {
	query := `
		INSERT INTO audit_logs (user_id, action, resource_type, resource_id, old_values, 
		                       new_values, ip_address, user_agent, status, error_message, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	if r.db.GetDriverName() == "mssql" {
		query = `
			INSERT INTO audit_logs (user_id, action, resource_type, resource_id, old_values, 
			                       new_values, ip_address, user_agent, status, error_message, created_at)
			VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10, @p11)
		`
	}

	log.CreatedAt = time.Now()

	_, err := r.db.GetDB().Exec(
		query,
		log.UserID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		log.OldValues,
		log.NewValues,
		log.IPAddress,
		log.UserAgent,
		log.Status,
		log.ErrorMessage,
		log.CreatedAt,
	)

	return err
}
```

**Verification**:
```powershell
# Build repositories
go build ./internal/repository
```

---

### Task 5: Create Service Layer
**Location**: `internal/services/`

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

	roles, err := s.roleRepo.GetUserRoles(userID)
	if err != nil {
		roles = []string{}
	}

	permissions, err := s.roleRepo.GetUserPermissions(userID)
	if err != nil {
		permissions = []string{}
	}

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
	user, err := s.userRepo.FindByID(id)
	if err != nil {
		return nil, err
	}

	roles, err := s.roleRepo.GetUserRoles(id)
	if err != nil {
		roles = []string{}
	}

	permissions, err := s.roleRepo.GetUserPermissions(id)
	if err != nil {
		permissions = []string{}
	}

	return &models.UserResponse{
		User:        user,
		Roles:       roles,
		Permissions: permissions,
	}, nil
}
```

**Verification**:
```powershell
# Build services
go build ./internal/services
```

---

### Task 6: Create Auth Handler
**Location**: `internal/handlers/`

#### 6.1 Create `internal/handlers/auth_handler.go`
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
// POST /api/auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// TODO: Add validation using validator library

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
// POST /api/auth/login
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
		
		// Return generic error for security
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
// POST /api/auth/refresh
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
// POST /api/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
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
// GET /api/auth/me
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
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

// getIPAddress extracts IP address from request
func getIPAddress(r *http.Request) string {
	// Try X-Forwarded-For header first
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return ip
	}

	// Try X-Real-IP header
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
```

**Verification**:
```powershell
# Build handlers
go build ./internal/handlers
```

---

### Task 7: Create Middleware
**Location**: `internal/middleware/`

#### 7.1 Create `internal/middleware/auth_middleware.go`
```go
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/HashanEranga/go-task-manager-service/pkg/jwt"
	"github.com/HashanEranga/go-task-manager-service/pkg/response"
)

type AuthMiddleware struct {
	tokenMgr *jwt.TokenManager
}

func NewAuthMiddleware(tokenMgr *jwt.TokenManager) *AuthMiddleware {
	return &AuthMiddleware{tokenMgr: tokenMgr}
}

// Authenticate validates JWT token and adds user info to context
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			response.Error(w, http.StatusUnauthorized, "Missing authorization header", nil)
			return
		}

		// Check Bearer token format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			response.Error(w, http.StatusUnauthorized, "Invalid authorization header format", nil)
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := m.tokenMgr.ValidateToken(tokenString)
		if err != nil {
			response.Error(w, http.StatusUnauthorized, "Invalid or expired token", err)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "username", claims.Username)
		ctx = context.WithValue(ctx, "email", claims.Email)
		ctx = context.WithValue(ctx, "roles", claims.Roles)
		ctx = context.WithValue(ctx, "permissions", claims.Permissions)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

#### 7.2 Create `internal/middleware/rbac_middleware.go`
```go
package middleware

import (
	"net/http"

	"github.com/HashanEranga/go-task-manager-service/pkg/response"
)

// RequirePermission checks if user has required permission
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get permissions from context
			permissions, ok := r.Context().Value("permissions").([]string)
			if !ok {
				response.Error(w, http.StatusForbidden, "Access denied", nil)
				return
			}

			// Check if user has required permission
			hasPermission := false
			for _, p := range permissions {
				if p == permission {
					hasPermission = true
					break
				}
			}

			if !hasPermission {
				response.Error(w, http.StatusForbidden, "Insufficient permissions", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole checks if user has required role
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get roles from context
			roles, ok := r.Context().Value("roles").([]string)
			if !ok {
				response.Error(w, http.StatusForbidden, "Access denied", nil)
				return
			}

			// Check if user has required role
			hasRole := false
			for _, r := range roles {
				if r == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				response.Error(w, http.StatusForbidden, "Insufficient permissions", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole checks if user has any of the required roles
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user roles from context
			userRoles, ok := r.Context().Value("roles").([]string)
			if !ok {
				response.Error(w, http.StatusForbidden, "Access denied", nil)
				return
			}

			// Check if user has any of the required roles
			hasRole := false
			for _, requiredRole := range roles {
				for _, userRole := range userRoles {
					if userRole == requiredRole {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				response.Error(w, http.StatusForbidden, "Insufficient permissions", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
```

**Verification**:
```powershell
# Build middleware
go build ./internal/middleware
```

---

### Task 8: Wire Up Router
**Location**: `cmd/server/main.go`

#### 8.1 Update `cmd/server/main.go`
Add after the existing database connection code (around line 50):

```go
// Initialize JWT Token Manager
tokenManager := jwt.NewTokenManager(
	cfg.JWT.Secret,
	cfg.JWT.Expiry,
	cfg.JWT.RefreshExpiry,
)

// Initialize repositories
userRepo := repository.NewUserRepository(db)
authRepo := repository.NewAuthRepository(db)
roleRepo := repository.NewRoleRepository(db)
auditRepo := repository.NewAuditRepository(db)

// Initialize services
authService := services.NewAuthService(userRepo, authRepo, roleRepo, auditRepo, tokenManager)
userService := services.NewUserService(userRepo, roleRepo)

// Initialize handlers
authHandler := handlers.NewAuthHandler(authService)

// Initialize middleware
authMiddleware := middleware.NewAuthMiddleware(tokenManager)
```

Then update the router section (around line 74):

```go
r.Route("/api", func(r chi.Router) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("TaskFlow API v1.0"))
	})

	// Public auth routes
	r.Route("/auth", func(r chi.Router) {
		r.Post("/register", authHandler.Register)
		r.Post("/login", authHandler.Login)
		r.Post("/refresh", authHandler.RefreshToken)

		// Protected routes (require authentication)
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware.Authenticate)
			r.Get("/me", authHandler.Me)
			r.Post("/logout", authHandler.Logout)
		})
	})

	// Example protected route with permission check
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware.Authenticate)
		// Future user management routes
		// r.With(middleware.RequirePermission("users.read")).Get("/users", userHandler.List)
	})
})
```

Don't forget to add imports at the top:

```go
import (
	// ... existing imports ...
	"github.com/HashanEranga/go-task-manager-service/internal/middleware"
	"github.com/HashanEranga/go-task-manager-service/internal/repository"
	"github.com/HashanEranga/go-task-manager-service/internal/services"
	"github.com/HashanEranga/go-task-manager-service/pkg/jwt"
)
```

**Verification**:
```powershell
# Build the application
go build -o bin/taskflow.exe cmd/server/main.go

# Run the application
go run cmd/server/main.go
```

---

### Task 9: Test Authentication Flow

#### 9.1 Start the server
```powershell
go run cmd/server/main.go
```

#### 9.2 Test Registration
```powershell
# Using curl (if available)
curl -X POST http://localhost:8080/api/auth/register `
  -H "Content-Type: application/json" `
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "Test@123456",
    "first_name": "Test",
    "last_name": "User"
  }'

# Using PowerShell Invoke-RestMethod
$body = @{
    username = "testuser"
    email = "test@example.com"
    password = "Test@123456"
    first_name = "Test"
    last_name = "User"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/auth/register" -Method Post -Body $body -ContentType "application/json"
```

#### 9.3 Test Login
```powershell
$loginBody = @{
    username = "testuser"
    password = "Test@123456"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json"

# Save tokens for next requests
$accessToken = $response.access_token
$refreshToken = $response.refresh_token
```

#### 9.4 Test Protected Endpoint (Get Profile)
```powershell
$headers = @{
    "Authorization" = "Bearer $accessToken"
}

Invoke-RestMethod -Uri "http://localhost:8080/api/auth/me" -Method Get -Headers $headers
```

#### 9.5 Test Token Refresh
```powershell
$refreshBody = @{
    refresh_token = $refreshToken
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/auth/refresh" -Method Post -Body $refreshBody -ContentType "application/json"
```

#### 9.6 Test Logout
```powershell
$logoutBody = @{
    refresh_token = $refreshToken
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/auth/logout" -Method Post -Body $logoutBody -ContentType "application/json" -Headers $headers
```

#### 9.7 Verify Database Audit Logs
```sql
-- PostgreSQL
SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 10;

-- Check refresh tokens
SELECT user_id, token, expires_at, is_revoked FROM refresh_tokens;

-- Check user roles
SELECT u.username, r.name as role
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id;
```

---

## Success Checklist

- [ ] All model files created in `internal/models/`
- [ ] Password utilities working in `pkg/security/`
- [ ] JWT utilities working in `pkg/jwt/`
- [ ] All repositories created and handle both databases
- [ ] Auth service implements register, login, refresh, logout
- [ ] Auth handler responds to all endpoints
- [ ] Auth middleware validates tokens correctly
- [ ] RBAC middleware enforces permissions
- [ ] Main router wired with all components
- [ ] User can register successfully
- [ ] User can login and receive tokens
- [ ] Protected endpoints require valid token
- [ ] Token refresh works correctly
- [ ] Account locks after failed attempts
- [ ] Audit logs are created for auth events
- [ ] Works with both PostgreSQL and SQL Server

---

## Troubleshooting

### Build Errors
```powershell
# Clean and rebuild
go clean -cache
go mod tidy
go build ./...
```

### Import Issues
```powershell
# Verify module name matches go.mod
go mod edit -module=github.com/HashanEranga/go-task-manager-service
```

### Database Connection Issues
- Verify database is running
- Check `.env` file has correct credentials
- Test with health endpoint: `curl http://localhost:8080/health/db`

### Token Validation Failing
- Check JWT_SECRET is set correctly in `.env`
- Ensure token expiry times are valid durations (15m, 168h)

---

## Next Steps After Phase 3

Once Phase 3 is complete and tested:
1. **Phase 4**: User Management (CRUD operations, profile updates)
2. **Phase 5**: Projects Module (create, update, delete projects)
3. **Phase 6**: Tasks Module (task CRUD, assignments, status workflow)
4. **Phase 7**: Collaboration (comments, attachments)
5. **Phase 8**: Testing & Deployment (unit tests, Docker, CI/CD)

---

**Phase 3 Status**: Ready for Implementation
**Estimated Time**: 6-8 hours
**Difficulty**: Moderate (requires understanding of JWT, RBAC, and repository pattern)
