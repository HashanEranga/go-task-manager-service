package models

import "time"

type RefreshToken struct {
	ID        int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    int64      `gorm:"not null;index" json:"user_id"`
	Token     string     `gorm:"unique;not null;size:500" json:"token"`
	ExpiresAt time.Time  `gorm:"not null;index" json:"expires_at"`
	IsRevoked bool       `gorm:"default:false" json:"is_revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	IPAddress *string    `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent *string    `gorm:"size:500" json:"user_agent,omitempty"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`

	User User `gorm:"foreignKey:UserID"`
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

func (rt *RefreshToken) IsValid() bool {
	return !rt.IsRevoked && time.Now().Before(rt.ExpiresAt)
}
