package models

import "time"

type Role struct {
	ID          int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	Name        string    `gorm:"unique;not null;size:50" json:"name"`
	Description *string   `gorm:"size:255" json:"description,omitempty"`
	IsActive    bool      `gorm:"default:true" json:"is_active"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	Users       []User       `gorm:"many2many:user_roles;" json:"-"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
}

func (Role) TableName() string {
	return "roles"
}

type UserRole struct {
	ID         int64     `gorm:"primaryKey;autoIncrement"`
	UserID     int64     `gorm:"not null"`
	RoleID     int64     `gorm:"not null"`
	AssignedAt time.Time `gorm:"autoCreateTime"`
	AssignedBy *int64

	User User `gorm:"foreignKey:UserID"`
	Role Role `gorm:"foreignKey:RoleID"`
}

func (UserRole) TableName() string {
	return "user_roles"
}
