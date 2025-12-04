package repository

import (
	"errors"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/models"
	"gorm.io/gorm"
)

var (
	ErrTokenNotFound = errors.New("token not found")
)

type AuthRepository struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

func (r *AuthRepository) SaveRefreshToken(token *models.RefreshToken) error {
	return r.db.Create(token).Error
}

func (r *AuthRepository) FindRefreshToken(tokenString string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	result := r.db.Where("token = ?", tokenString).First(&token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, result.Error
	}
	return &token, nil
}

func (r *AuthRepository) RevokeRefreshToken(tokenString string) error {
	now := time.Now()
	return r.db.Model(&models.RefreshToken{}).
		Where("token = ?", tokenString).
		Updates(map[string]interface{}{
			"is_revoked": true,
			"revoked_at": now,
		}).Error
}

func (r *AuthRepository) RevokeAllUserTokens(userID int64) error {
	now := time.Now()
	return r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND is_revoked = ?", userID, false).
		Updates(map[string]interface{}{
			"is_revoked": true,
			"revoked_at": now,
		}).Error
}

func (r *AuthRepository) DeleteExpiredTokens() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&models.RefreshToken{}).Error
}
