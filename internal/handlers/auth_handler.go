package handlers

import (
	"encoding/json"
	"errors"
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

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	authResp, err := h.authService.Register(&req, ipAddress, userAgent)
	if err != nil {
		logger.Error("Registration failed", err)
		response.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	response.JSON(w, http.StatusCreated, authResp)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	authResp, err := h.authService.Login(&req, ipAddress, userAgent)
	if err != nil {
		logger.Error("Login failed", err)

		if errors.Is(err, services.ErrInvalidCredentials) {
			response.Error(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		if errors.Is(err, services.ErrAccountLocked) {
			response.Error(w, http.StatusForbidden, "Account is locked")
			return
		}
		if errors.Is(err, services.ErrAccountInactive) {
			response.Error(w, http.StatusForbidden, "Account is inactive")
			return
		}

		response.Error(w, http.StatusInternalServerError, "Login failed")
		return
	}

	response.JSON(w, http.StatusOK, authResp)
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	authResp, err := h.authService.RefreshToken(req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		response.Error(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	response.JSON(w, http.StatusOK, authResp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(int64)
	if !ok {
		response.Error(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req models.RefreshTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return
	}

	errLogout := h.authService.Logout(req.RefreshToken, userID)
	if errLogout != nil {
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user_id").(int64)
	if !ok {
		response.Error(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	userProfile, err := h.authService.GetUserProfile(userID)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, "Failed to get user profile")
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
