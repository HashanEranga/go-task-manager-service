package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	App      AppConfig
}

type ServerConfig struct {
	Port         string
	Host         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type DatabaseConfig struct {
	Driver   string // "postgres" or "mssql"
	Postgres PostgresConfig
	MSSQL    MSSQLConfig
}

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type MSSQLConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
}

type JWTConfig struct {
	Secret        string
	Expiry        time.Duration
	RefreshExpiry time.Duration
}

type AppConfig struct {
	Environment string
	LogLevel    string
}

func Load() (*Config, error) {

	viper.SetDefault("SERVER_PORT", "8080")
	viper.SetDefault("SERVER_HOST", "0.0.0.0")
	viper.SetDefault("DB_DRIVER", "postgres")
	viper.SetDefault("APP_ENV", "development")
	viper.SetDefault("LOG_LEVEL", "info")

	viper.SetConfigFile(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		// .env file is optional, so we just log the error
		// Configuration can still work with environment variables
	}

	cfg := &Config{
		Server: ServerConfig{
			Port:         viper.GetString("SERVER_PORT"),
			Host:         viper.GetString("SERVER_HOST"),
			ReadTimeout:  viper.GetDuration("SERVER_READ_TIMEOUT"),
			WriteTimeout: viper.GetDuration("SERVER_WRITE_TIMEOUT"),
		},
		Database: DatabaseConfig{
			Driver: viper.GetString("DB_DRIVER"),
			Postgres: PostgresConfig{
				Host:     viper.GetString("POSTGRES_HOST"),
				Port:     viper.GetString("POSTGRES_PORT"),
				User:     viper.GetString("POSTGRES_USER"),
				Password: viper.GetString("POSTGRES_PASSWORD"),
				DBName:   viper.GetString("POSTGRES_DB"),
				SSLMode:  viper.GetString("POSTGRES_SSLMODE"),
			},
			MSSQL: MSSQLConfig{
				Host:     viper.GetString("MSSQL_HOST"),
				Port:     viper.GetString("MSSQL_PORT"),
				User:     viper.GetString("MSSQL_USER"),
				Password: viper.GetString("MSSQL_PASSWORD"),
				DBName:   viper.GetString("MSSQL_DB"),
			},
		},
		JWT: JWTConfig{
			Secret:        viper.GetString("JWT_SECRET"),
			Expiry:        viper.GetDuration("JWT_EXPIRY"),
			RefreshExpiry: viper.GetDuration("JWT_REFRESH_EXPIRY"),
		},
		App: AppConfig{
			Environment: viper.GetString("APP_ENV"),
			LogLevel:    viper.GetString("LOG_LEVEL"),
		},
	}

	return cfg, nil
}

func (c *Config) GetDatabaseDriver() string {
	return c.Database.Driver
}

func (c *Config) IsProduction() bool {
	return c.App.Environment == "production"
}
