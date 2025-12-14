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

func (r *UserRepository) FindByUsername(userName string) (*models.User, error) {
	var user models.User
	result := r.db.Where("username = ?", userName).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

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

func (r *UserRepository) FindById(id int64) (*models.User, error) {
	var user models.User
	result := r.db.Where("id = ?", id).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

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

func (r *UserRepository) UpdateLastLogin(userID int64) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"last_login_at":         time.Now(),
		"failed_login_attempts": 0,
		"locked_until":          nil,
	}).Error
}

func (r *UserRepository) IncrementFailedLoginAttempts(userID int64) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).
		UpdateColumn("failed_login_attempts", gorm.Expr("failed_login_attempts + ?", 1)).Error
}

func (r *UserRepository) LockAccount(userID int64, until time.Time) error {
	return r.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"locked_until": until,
	}).Error
}

func (r *UserRepository) AssignRole(userID, roleID int64, assignedBy *int64) error {
	userRole := models.UserRole{
		UserID:     userID,
		RoleID:     roleID,
		AssignedBy: assignedBy,
	}
	return r.db.Create(&userRole).Error
}

// ListUsers retrieves paginated list of users with filtering
func (r *UserRepository) ListUsers(offset, limit int, filters map[string]interface{}) ([]models.User, int64, error) {
	var users []models.User
	var total int64

	query := r.db.Model(&models.User{})

	// Apply filters
	if username, ok := filters["username"]; ok && username != "" {
		query = query.Where("username ILIKE ?", "%"+username.(string)+"%")
	}
	if email, ok := filters["email"]; ok && email != "" {
		query = query.Where("email ILIKE ?", "%"+email.(string)+"%")
	}
	if isActive, ok := filters["is_active"]; ok {
		query = query.Where("is_active = ?", isActive)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results with roles
	err := query.
		Preload("Roles").
		Offset(offset).
		Limit(limit).
		Order("created_at DESC").
		Find(&users).Error

	return users, total, err
}

// Update updates user information
func (r *UserRepository) Update(user *models.User) error {
	result := r.db.Save(user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return result.Error
	}
	return nil
}

// UpdateFields updates specific user fields
func (r *UserRepository) UpdateFields(userID int64, updates map[string]interface{}) error {
	result := r.db.Model(&models.User{}).Where("id = ?", userID).Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// Delete performs soft delete (deactivate) on user
func (r *UserRepository) Delete(userID int64) error {
	// In this implementation, "delete" means deactivating the account
	return r.UpdateFields(userID, map[string]interface{}{
		"is_active": false,
	})
}

// RemoveRole removes a role from user
func (r *UserRepository) RemoveRole(userID, roleID int64) error {
	return r.db.Exec("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", userID, roleID).Error
}

// GetUserRoles retrieves all roles for a user
func (r *UserRepository) GetUserRoles(userID int64) ([]models.Role, error) {
	var user models.User
	err := r.db.Preload("Roles").First(&user, userID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user.Roles, nil
}
