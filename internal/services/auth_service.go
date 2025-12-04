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

func (s *AuthService) Register(req *models.RegisterRequest, ipAddress, userAgent string) (*models.AuthResponse, error) {
	if err := security.ValidatePasswordStrength(req.Password); err != nil {
		s.logAudit(nil, "user.register", "users", nil, "failure", err.Error(), ipAddress, userAgent)
		return nil, err
	}

	if _, err := s.userRepo.FindByUsername(req.Username); err == nil {
		return nil, errors.New("username already exists")
	}

	if _, err := s.userRepo.FindByEmail(req.Email); err == nil {
		return nil, errors.New("email already exists")
	}

	passwordHash, err := security.HashPassword(req.Password)
	if err != nil {
		logger.Error("Failed to hash password", err)
		return nil, errors.New("failed to process password")
	}

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

	roleID, err := s.roleRepo.GetRoleIDByName("USER")
	if err == nil {
		err := s.userRepo.AssignRole(user.ID, roleID, nil)
		if err != nil {
			return nil, err
		}
	}

	s.logAudit(&user.ID, "user.register", "users", &user.ID, "success", "", ipAddress, userAgent)

	return s.generateTokens(user, ipAddress, userAgent)
}

func (s *AuthService) Login(req *models.LoginRequest, ipAddress, userAgent string) (*models.AuthResponse, error) {
	user, err := s.userRepo.FindByUsername(req.Username)
	if err != nil {
		s.logAudit(nil, "user.login", "users", nil, "failure", "user not found", ipAddress, userAgent)
		return nil, ErrInvalidCredentials
	}

	if user.IsAccountLocked() {
		s.logAudit(&user.ID, "user.login", "users", &user.ID, "failure", "account locked", ipAddress, userAgent)
		return nil, ErrAccountLocked
	}

	if !user.IsActive {
		s.logAudit(&user.ID, "user.login", "users", &user.ID, "failure", "account inactive", ipAddress, userAgent)
		return nil, ErrAccountInactive
	}

	if err := security.CheckPasswordHash(req.Password, user.PasswordHash); err != nil {
		errIncreaseFailedLoginAttempt := s.userRepo.IncrementFailedLoginAttempts(user.ID)
		if errIncreaseFailedLoginAttempt != nil {
			return nil, errIncreaseFailedLoginAttempt
		}

		if user.FailedLoginAttempts+1 >= MaxFailedLoginAttempts {
			lockUntil := time.Now().Add(AccountLockDuration)
			errLockAcc := s.userRepo.LockAccount(user.ID, lockUntil)
			if errLockAcc != nil {
				return nil, errLockAcc
			}
			s.logAudit(&user.ID, "user.login", "users", &user.ID, "failure", "account locked after max attempts", ipAddress, userAgent)
			return nil, ErrAccountLocked
		}

		s.logAudit(&user.ID, "user.login", "users", &user.ID, "failure", "invalid password", ipAddress, userAgent)
		return nil, ErrInvalidCredentials
	}

	errUpdateLastLogin := s.userRepo.UpdateLastLogin(user.ID)
	if errUpdateLastLogin != nil {
		return nil, errUpdateLastLogin
	}

	s.logAudit(&user.ID, "user.login", "users", &user.ID, "success", "", ipAddress, userAgent)

	return s.generateTokens(user, ipAddress, userAgent)
}

func (s *AuthService) RefreshToken(refreshTokenStr string, ipAddress, userAgent string) (*models.AuthResponse, error) {
	token, err := s.authRepo.FindRefreshToken(refreshTokenStr)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if !token.IsValid() {
		return nil, ErrInvalidToken
	}

	user, err := s.userRepo.FindById(token.UserID)
	if err != nil {
		return nil, err
	}

	if !user.CanAttemptLogin() {
		return nil, ErrAccountInactive
	}

	errRefreshToken := s.authRepo.RevokeRefreshToken(refreshTokenStr)
	if errRefreshToken != nil {
		return nil, errRefreshToken
	}

	return s.generateTokens(user, ipAddress, userAgent)
}

func (s *AuthService) Logout(refreshTokenStr string, userID int64) error {
	if refreshTokenStr != "" {
		errRevokeToken := s.authRepo.RevokeRefreshToken(refreshTokenStr)
		if errRevokeToken != nil {
			return errRevokeToken
		}
	}
	return nil
}

func (s *AuthService) GetUserProfile(userID int64) (*models.UserResponse, error) {
	user, err := s.userRepo.FindById(userID)
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

func (s *AuthService) generateTokens(user *models.User, ipAddress, userAgent string) (*models.AuthResponse, error) {
	roles, _ := s.roleRepo.GetUserRoles(user.ID)
	permissions, _ := s.roleRepo.GetUserPermissions(user.ID)

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

	refreshToken, err := s.tokenMgr.GenerateRefreshToken(user.ID, user.Username)
	if err != nil {
		return nil, err
	}

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
