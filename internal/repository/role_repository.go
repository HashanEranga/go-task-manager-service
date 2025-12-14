package repository

import (
	"errors"

	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"gorm.io/gorm"
)

type RoleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

func (r *RoleRepository) GetUserRoles(userID int64) ([]string, error) {
	var roles []string
	err := r.db.Table("roles").
		Select("roles.name").
		Joins("INNER JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ? AND roles.is_active = ?", userID, true).
		Pluck("name", &roles).Error

	return roles, err
}

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

func (r *RoleRepository) GetRoleIDByName(name string) (int64, error) {
	var roleID int64
	err := r.db.Table("roles").Select("id").Where("name = ?", name).Scan(&roleID).Error
	return roleID, err
}

func (r *RoleRepository) HasPermission(userID int64, permissionName string) (bool, error) {
	var count int64
	err := r.db.Table("permissions").
		Joins("INNER JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("INNER JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ? AND permissions.name = ?", userID, permissionName).
		Count(&count).Error

	return count > 0, err
}

// FindByID finds a role by ID
func (r *RoleRepository) FindByID(id int64) (*models.Role, error) {
	var role models.Role
	result := r.db.First(&role, id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("role not found")
		}
		return nil, result.Error
	}
	return &role, nil
}
