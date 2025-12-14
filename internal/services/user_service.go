package services

import (
	"errors"
	"fmt"

	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"github.com/HashanEranga/go-task-manager-service/internal/repository"
	"github.com/HashanEranga/go-task-manager-service/pkg/security"
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

func (s *UserService) GetByID(id int64) (*models.User, error) {
	return s.userRepo.FindById(id)
}

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

// ListUsers retrieves paginated users
func (s *UserService) ListUsers(page, pageSize int, filters map[string]interface{}) ([]models.User, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize
	return s.userRepo.ListUsers(offset, pageSize, filters)
}

// CreateUser creates a new user account (admin only)
func (s *UserService) CreateUser(req *models.CreateUserRequest) (*models.User, error) {
	// Check if username or email already exists
	if existingUser, _ := s.userRepo.FindByUsername(req.Username); existingUser != nil {
		return nil, errors.New("username already exists")
	}
	if existingUser, _ := s.userRepo.FindByEmail(req.Email); existingUser != nil {
		return nil, errors.New("email already exists")
	}

	// Validate password strength
	if err := security.ValidatePasswordStrength(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := security.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Phone:        req.Phone,
		IsActive:     true,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}

	// Assign default "USER" role if no roles specified
	if len(req.RoleIDs) == 0 {
		roleID, err := s.roleRepo.GetRoleIDByName("USER")
		if err == nil {
			_ = s.userRepo.AssignRole(user.ID, roleID, nil)
		}
	} else {
		// Assign specified roles
		for _, roleID := range req.RoleIDs {
			_ = s.userRepo.AssignRole(user.ID, roleID, nil)
		}
	}

	// Reload user with roles
	return s.userRepo.FindByIDWithRoles(user.ID)
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(userID int64, req *models.UpdateUserRequest) (*models.User, error) {
	user, err := s.userRepo.FindById(userID)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.Email != nil {
		// Check if email is already taken by another user
		if existingUser, _ := s.userRepo.FindByEmail(*req.Email); existingUser != nil && existingUser.ID != userID {
			return nil, errors.New("email already exists")
		}
		user.Email = *req.Email
	}
	if req.FirstName != nil {
		user.FirstName = req.FirstName
	}
	if req.LastName != nil {
		user.LastName = req.LastName
	}
	if req.Phone != nil {
		user.Phone = req.Phone
	}

	if err := s.userRepo.Update(user); err != nil {
		return nil, err
	}

	return s.userRepo.FindByIDWithRoles(userID)
}

// DeleteUser soft deletes a user (deactivates account)
func (s *UserService) DeleteUser(userID int64) error {
	_, err := s.userRepo.FindById(userID)
	if err != nil {
		return err
	}
	return s.userRepo.Delete(userID)
}

// ActivateUser activates a user account
func (s *UserService) ActivateUser(userID int64) error {
	return s.userRepo.UpdateFields(userID, map[string]interface{}{
		"is_active": true,
	})
}

// DeactivateUser deactivates a user account
func (s *UserService) DeactivateUser(userID int64) error {
	return s.userRepo.UpdateFields(userID, map[string]interface{}{
		"is_active": false,
	})
}

// AssignRole assigns a role to a user
func (s *UserService) AssignRole(userID, roleID int64, assignedBy *int64) error {
	// Verify user exists
	_, err := s.userRepo.FindById(userID)
	if err != nil {
		return err
	}

	// Verify role exists
	_, err = s.roleRepo.FindByID(roleID)
	if err != nil {
		return errors.New("role not found")
	}

	return s.userRepo.AssignRole(userID, roleID, assignedBy)
}

// RevokeRole removes a role from a user
func (s *UserService) RevokeRole(userID, roleID int64) error {
	return s.userRepo.RemoveRole(userID, roleID)
}
