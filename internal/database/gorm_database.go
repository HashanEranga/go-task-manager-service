package database

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/HashanEranga/go-task-manager-service/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type GormDatabase struct {
	db         *gorm.DB
	driverName string
}

func (g GormDatabase) Connect() error {
	return nil
}

func (g GormDatabase) Close() error {
	sqlDB, err := g.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (g GormDatabase) GetDB() *sql.DB {
	sqlDB, _ := g.db.DB()
	return sqlDB
}

func (g GormDatabase) GetGormDB() *gorm.DB {
	return g.db
}

func (g GormDatabase) Ping() error {
	sqlDB, err := g.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func (g GormDatabase) GetDriverName() string {
	return g.driverName
}

func NewGormDatabase(cfg *config.Config) (Database, error) {
	var dialector gorm.Dialector
	var driverName string

	switch cfg.GetDatabaseDriver() {
	case "postgres":
		dsn := fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			cfg.Database.Postgres.Host,
			cfg.Database.Postgres.Port,
			cfg.Database.Postgres.User,
			cfg.Database.Postgres.Password,
			cfg.Database.Postgres.DBName,
			cfg.Database.Postgres.SSLMode,
		)
		dialector = postgres.Open(dsn)
		driverName = "postgres"

	case "mssql":
		dsn := fmt.Sprintf(
			"sqlserver://%s:%s@%s:%s?database=%s",
			cfg.Database.MSSQL.User,
			cfg.Database.MSSQL.Password,
			cfg.Database.MSSQL.Host,
			cfg.Database.MSSQL.Port,
			cfg.Database.MSSQL.DBName,
		)
		dialector = sqlserver.Open(dsn)
		driverName = "mssql"
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.GetDatabaseDriver())
	}

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	}

	db, err := gorm.Open(dialector, gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	return &GormDatabase{
		db:         db,
		driverName: driverName,
	}, nil
}
