package models

import "time"

type AuditLog struct {
	ID           int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID       *int64    `gorm:"index" json:"user_id,omitempty"`
	Action       string    `gorm:"not null;size:100;index" json:"action"`
	ResourceType string    `gorm:"not null;size:50;index" json:"resource_type"`
	ResourceID   *int64    `gorm:"index" json:"resource_id,omitempty"`
	OldValues    *string   `gorm:"type:text" json:"old_values,omitempty"`
	NewValues    *string   `gorm:"type:text" json:"new_values,omitempty"`
	IPAddress    *string   `gorm:"size:45" json:"ip_address,omitempty"`
	UserAgent    *string   `gorm:"size:500" json:"user_agent,omitempty"`
	Status       string    `gorm:"not null;size:20" json:"status"`
	ErrorMessage *string   `gorm:"type:text" json:"error_message,omitempty"`
	CreatedAt    time.Time `gorm:"autoCreateTime;index" json:"created_at"`

	User *User `gorm:"foreignKey:UserID"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
