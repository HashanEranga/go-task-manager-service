package database

import (
	"database/sql"

	"github.com/HashanEranga/go-task-manager-service/internal/config"
	"gorm.io/gorm"
)

type Database interface {
	Connect() error
	Close() error
	GetDB() *sql.DB
	Ping() error
	GetDriverName() string
	GetGormDB() *gorm.DB
}

func NewDatabase(cfg *config.Config) (Database, error) {
	return NewGormDatabase(cfg)
}
