package models

import (
	"time"
)

type User struct {
	ID                  int64      `gorm:"primaryKey;autoIncrement" json:"id"`
	Username            string     `gorm:"unique;not null;size:50" json:"username"`
	Email               string     `gorm:"unique;not null;size:255" json:"email"`
	PasswordHash        string     `gorm:"not null;size:255" json:"-"`
	FirstName           *string    `gorm:"size:100" json:"first_name,omitempty"`
	LastName            *string    `gorm:"size:100" json:"last_name,omitempty"`
	Phone               *string    `gorm:"size:20" json:"phone,omitempty"`
	IsActive            bool       `gorm:"default:true" json:"is_active"`
	IsEmailVerified     bool       `gorm:"default:false" json:"is_email_verified"`
	EmailVerifiedAt     *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	PasswordChangedAt   *time.Time `json:"password_changed_at,omitempty"`
	FailedLoginAttempts int        `gorm:"default:0" json:"-"`
	LockedUntil         *time.Time `json:"locked_until,omitempty"`
	CreatedAt           time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt           time.Time  `gorm:"autoUpdateTime" json:"updated_at"`

	Roles         []Role         `gorm:"many2many:user_roles;" json:"roles,omitempty"`
	RefreshTokens []RefreshToken `gorm:"foreignKey:UserID" json:"-"`
	AuditLogs     []AuditLog     `gorm:"foreignKey:UserID" json:"-"`
}

func (User) TableName() string {
	return "users"
}

func (u *User) IsAccountLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}

func (u *User) CanAttemptLogin() bool {
	return u.IsActive && !u.IsAccountLocked()
}
