package handlers

import (
	"net/http"

	"github.com/HashanEranga/go-task-manager-service/internal/database"
	"github.com/HashanEranga/go-task-manager-service/pkg/response"
)

type HealthHandler struct {
	db database.Database
}

func NewHealthHandler(db database.Database) *HealthHandler {
	return &HealthHandler{db: db}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	response.Success(w, "Server is running", map[string]string{
		"status": "ok",
	})
}

func (h *HealthHandler) HealthDB(w http.ResponseWriter, r *http.Request) {
	err := h.db.Ping()
	if err != nil {
		response.Error(w, http.StatusServiceUnavailable, "Database connection failed")
		return
	}

	response.Success(w, "Database is connected", map[string]string{
		"status": "ok",
		"driver": h.db.GetDriverName(),
	})
}
