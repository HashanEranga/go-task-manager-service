package repository

import (
	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"gorm.io/gorm"
)

type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Log(log *models.AuditLog) error {
	return r.db.Create(log).Error
}
