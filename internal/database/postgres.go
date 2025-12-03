package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/config"
	_ "github.com/lib/pq"
)

type PostgresDB struct {
	db  *sql.DB
	cfg *config.Config
}

func NewPostgresDB(cfg *config.Config) *PostgresDB {
	return &PostgresDB{
		cfg: cfg,
	}
}

func (p *PostgresDB) Connect() error {
	pgCfg := p.cfg.Database.Postgres

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		pgCfg.Host,
		pgCfg.Port,
		pgCfg.User,
		pgCfg.Password,
		pgCfg.DBName,
		pgCfg.SSLMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open postgres connection: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	p.db = db
	return nil
}

func (p *PostgresDB) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *PostgresDB) GetDB() *sql.DB {
	return p.db
}

func (p *PostgresDB) GetDriverName() string {
	return "postgres"
}

func (m *PostgresDB) Ping() error {
	return m.db.Ping()
}
