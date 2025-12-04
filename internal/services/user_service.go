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
