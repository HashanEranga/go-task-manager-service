package models

import "time"

type Permission struct {
	ID          int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	Name        string    `gorm:"unique;not null;size:100" json:"name"`
	Resource    string    `gorm:"not null;size:50" json:"resource"`
	Action      string    `gorm:"not null;size:50" json:"action"`
	Description *string   `gorm:"size:255" json:"description,omitempty"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`

	Roles []Role `gorm:"many2many:role_permissions;" json:"-"`
}

func (Permission) TableName() string {
	return "permissions"
}

type RolePermission struct {
	ID           int64     `gorm:"primaryKey;autoIncrement"`
	RoleID       int64     `gorm:"not null"`
	PermissionID int64     `gorm:"not null"`
	AssignedAt   time.Time `gorm:"autoCreateTime"`

	Role       Role       `gorm:"foreignKey:RoleID"`
	Permission Permission `gorm:"foreignKey:PermissionID"`
}

func (RolePermission) TableName() string {
	return "role_permissions"
}
