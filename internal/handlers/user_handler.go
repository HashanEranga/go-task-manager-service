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

// ListUsers handles GET /api/users
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

// GetUser handles GET /api/users/:id
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

// CreateUser handles POST /api/users
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

// UpdateUser handles PUT /api/users/:id
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

// DeleteUser handles DELETE /api/users/:id
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

// ActivateUser handles PATCH /api/users/:id/activate
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

// DeactivateUser handles PATCH /api/users/:id/deactivate
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

// AssignRole handles POST /api/users/:id/roles
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

// RevokeRole handles DELETE /api/users/:id/roles/:roleId
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
