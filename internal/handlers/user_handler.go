package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"github.com/HashanEranga/go-task-manager-service/internal/services"
	"github.com/HashanEranga/go-task-manager-service/pkg/logger"
	"github.com/HashanEranga/go-task-manager-service/pkg/response"
	"github.com/go-chi/chi/v5"
)

type UserHandler struct {
	userService *services.UserService
}

func NewUserHandler(userService *services.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// ListUsers godoc
// @Summary List all users
// @Description Get paginated list of users with optional filters
// @Tags users
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param username query string false "Filter by username"
// @Param email query string false "Filter by email"
// @Param is_active query boolean false "Filter by active status"
// @Success 200 {object} models.ListUsersResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /users [get]
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	username := r.URL.Query().Get("username")
	email := r.URL.Query().Get("email")
	isActiveStr := r.URL.Query().Get("is_active")

	// Default pagination
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}

	// Build filters
	filters := make(map[string]interface{})
	if username != "" {
		filters["username"] = username
	}
	if email != "" {
		filters["email"] = email
	}
	if isActiveStr != "" {
		isActive, _ := strconv.ParseBool(isActiveStr)
		filters["is_active"] = isActive
	}

	// Get users
	users, total, err := h.userService.ListUsers(page, pageSize, filters)
	if err != nil {
		logger.Error("Failed to list users", err)
		response.Error(w, http.StatusInternalServerError, "Failed to retrieve users")
		return
	}

	// Convert to response DTOs
	userItems := make([]models.UserListItem, len(users))
	for i, user := range users {
		roles := make([]string, len(user.Roles))
		for j, role := range user.Roles {
			roles[j] = role.Name
		}

		userItems[i] = models.UserListItem{
			ID:              user.ID,
			Username:        user.Username,
			Email:           user.Email,
			FirstName:       user.FirstName,
			LastName:        user.LastName,
			IsActive:        user.IsActive,
			IsEmailVerified: user.IsEmailVerified,
			Roles:           roles,
			CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	resp := models.ListUsersResponse{
		Users:      userItems,
		Page:       page,
		PageSize:   pageSize,
		TotalCount: total,
		TotalPages: totalPages,
	}

	response.JSON(w, http.StatusOK, resp)
}

// GetUser godoc
// @Summary Get user by ID
// @Description Get detailed user information by ID
// @Tags users
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /users/{id} [get]
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	userResp, err := h.userService.GetUserWithRoles(userID)
	if err != nil {
		response.Error(w, http.StatusNotFound, "User not found")
		return
	}

	response.JSON(w, http.StatusOK, userResp)
}

// CreateUser godoc
// @Summary Create new user
// @Description Create a new user account (admin only)
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.CreateUserRequest true "Create user request"
// @Success 201 {object} models.User
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /users [post]
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req models.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := h.userService.CreateUser(&req)
	if err != nil {
		logger.Error("Failed to create user", err)
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	response.JSON(w, http.StatusCreated, user)
}

// UpdateUser godoc
// @Summary Update user
// @Description Update user information
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body models.UpdateUserRequest true "Update user request"
// @Success 200 {object} models.User
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /users/{id} [put]
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := h.userService.UpdateUser(userID, &req)
	if err != nil {
		logger.Error("Failed to update user", err)
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	response.JSON(w, http.StatusOK, user)
}

// DeleteUser godoc
// @Summary Delete user
// @Description Soft delete user (deactivate account)
// @Tags users
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /users/{id} [delete]
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	if err := h.userService.DeleteUser(userID); err != nil {
		logger.Error("Failed to delete user", err)
		response.Error(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "User deactivated successfully",
	})
}

// ActivateUser godoc
// @Summary Activate user
// @Description Activate a deactivated user account
// @Tags users
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /users/{id}/activate [patch]
func (h *UserHandler) ActivateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	if err := h.userService.ActivateUser(userID); err != nil {
		logger.Error("Failed to activate user", err)
		response.Error(w, http.StatusInternalServerError, "Failed to activate user")
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "User activated successfully",
	})
}

// DeactivateUser godoc
// @Summary Deactivate user
// @Description Deactivate a user account
// @Tags users
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /users/{id}/deactivate [patch]
func (h *UserHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	if err := h.userService.DeactivateUser(userID); err != nil {
		logger.Error("Failed to deactivate user", err)
		response.Error(w, http.StatusInternalServerError, "Failed to deactivate user")
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "User deactivated successfully",
	})
}

// AssignRole godoc
// @Summary Assign role to user
// @Description Assign a role to a user
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body models.AssignRoleRequest true "Assign role request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /users/{id}/roles [post]
func (h *UserHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var req models.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get admin user ID from context
	adminID := r.Context().Value("user_id").(int64)

	if err := h.userService.AssignRole(userID, req.RoleID, &adminID); err != nil {
		logger.Error("Failed to assign role", err)
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "Role assigned successfully",
	})
}

// RevokeRole godoc
// @Summary Revoke role from user
// @Description Remove a role from a user
// @Tags users
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param roleId path int true "Role ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /users/{id}/roles/{roleId} [delete]
func (h *UserHandler) RevokeRole(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	roleID, err := strconv.ParseInt(chi.URLParam(r, "roleId"), 10, 64)
	if err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid role ID")
		return
	}

	if err := h.userService.RevokeRole(userID, roleID); err != nil {
		logger.Error("Failed to revoke role", err)
		response.Error(w, http.StatusInternalServerError, "Failed to revoke role")
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "Role revoked successfully",
	})
}
