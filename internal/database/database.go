package database

import (
	"database/sql"
	"fmt"

	"github.com/HashanEranga/go-task-manager-service/internal/config"
)

type Database interface {
	Connect() error
	Close() error
	GetDB() *sql.DB
	Ping() error
	GetDriverName() string
}

func NewDatabase(cfg *config.Config) (Database, error) {
	switch cfg.GetDatabaseDriver() {
	case "mssql":
		return NewMSSQLDB(cfg), nil
	case "postgres":
		return NewPostgresDB(cfg), nil
	default:
		return nil, fmt.Errorf("Unsupported database driver: %s", cfg.GetDatabaseDriver())
	}
}
