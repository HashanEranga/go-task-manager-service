package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/config"
)

type MSSQLDB struct {
	db  *sql.DB
	cfg *config.Config
}

func NewMSSQLDB(cfg *config.Config) *MSSQLDB {
	return &MSSQLDB{
		cfg: cfg,
	}
}

func (m *MSSQLDB) Connect() error {
	msCfg := m.cfg.Database.MSSQL

	connStr := fmt.Sprintf(
		"sqlserver://%s:%s@%s:%s?database=%s",
		msCfg.User,
		msCfg.Password,
		msCfg.Host,
		msCfg.Port,
		msCfg.DBName,
	)

	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		return fmt.Errorf("failed to open mssql connection: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping mssql: %w", err)
	}

	m.db = db
	return nil
}

func (m *MSSQLDB) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

func (m *MSSQLDB) GetDB() *sql.DB {
	return m.db
}

func (m *MSSQLDB) Ping() error {
	return m.db.Ping()
}

func (m *MSSQLDB) GetDriverName() string {
	return "mssql"
}
