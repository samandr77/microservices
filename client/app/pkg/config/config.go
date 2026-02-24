package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	env "github.com/caarlos0/env/v7"
	"github.com/joho/godotenv"
)

const (
	HoursPerDay = 24
)

type Config struct {
	HTTPPort         int    `env:"HTTP_PORT"`
	PostgresDSN      string `env:"POSTGRES_DSN"`
	PostgresMaxConns int32  `env:"POSTGRES_MAX_CONNS"`
	SupportEmail     string `env:"SUPPORT_EMAIL"`
	AuthServiceURL   string `env:"AUTH_SERVICE_URL"`
	LogLevel         string `env:"LOG_LEVEL" envDefault:"info"`
	UserService      UserServiceConfig

	// TLS / mTLS
	ServerCert           string `env:"TLS_SERVER_CERT"`
	ServerKey            string `env:"TLS_SERVER_KEY"`
	CACert               string `env:"TLS_CA_CERT"`
	ClientCert           string `env:"TLS_CLIENT_CERT"`
	ClientKey            string `env:"TLS_CLIENT_KEY"`
	MTLSEnabled          bool   `env:"MTLS_ENABLED" envDefault:"false"`
	SecurityServiceToken string `env:"SECURITY_SERVICE_TOKEN"`
}

type UserServiceConfig struct {
	TempBlockDurationMinutes  int `env:"TEMP_BLOCK_DURATION_MINUTES" envDefault:"15"`
	TempBlocksPerDayLimit     int `env:"TEMP_BLOCKS_PER_DAY_LIMIT" envDefault:"3"`
	BlockCheckIntervalMinutes int `env:"BLOCK_CHECK_INTERVAL_MINUTES" envDefault:"5"`

	AccountRecoveryPeriodDays int `env:"ACCOUNT_RECOVERY_PERIOD_DAYS" envDefault:"180"`

	MaxLoginAttempts       int           `env:"MAX_LOGIN_ATTEMPTS" envDefault:"5"`
	LockoutDurationMinutes int           `env:"LOCKOUT_DURATION_MINUTES" envDefault:"15"`
	TokenCleanupInterval   time.Duration `env:"TOKEN_CLEANUP_INTERVAL" envDefault:"720h"`
	BlockPeriodHours       int           `env:"BLOCK_PERIOD_HOURS" envDefault:"24"`

	DeletedAccountsCleanupInterval int `env:"DELETED_ACCOUNTS_CLEANUP_INTERVAL_HOURS" envDefault:"168"`
}

func New(envPath string) (Config, error) {
	var c Config

	err := godotenv.Load(envPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	err = env.Parse(&c)
	if err != nil {
		return Config{}, err
	}

	// Проверяем наличие файлов TLS (только если реально нужны)
	requiredFiles := []struct {
		name string
		val  string
	}{
		{"TLS_SERVER_CERT", c.ServerCert},
		{"TLS_SERVER_KEY", c.ServerKey},
	}

	if c.MTLSEnabled {
		requiredFiles = append(requiredFiles,
			struct{ name, val string }{"TLS_CA_CERT", c.CACert},
			struct{ name, val string }{"TLS_CLIENT_CERT", c.ClientCert},
			struct{ name, val string }{"TLS_CLIENT_KEY", c.ClientKey},
		)
	}

	for _, path := range requiredFiles {
		if _, err := os.Stat(path.val); os.IsNotExist(err) {
			return Config{}, fmt.Errorf("missing TLS file for %s: %s", path.name, path.val)
		}
	}

	return c, nil
}
