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
	UserServiceURL   string `env:"USER_SERVICE_URL"`
	LogLevel         string `env:"LOG_LEVEL" envDefault:"info"`
	JWT              JWTConfig
	OTP              OTPConfig
	KafkaBrokers     []string `env:"KAFKA_BROKERS" envSeparator:","`
	KafkaTopic       string   `env:"KAFKA_NOTIFICATION_TOPIC"`

	// Sber ID
	SberID SberIDConfig

	// TLS / mTLS
	ServerCert  string `env:"TLS_SERVER_CERT"`
	ServerKey   string `env:"TLS_SERVER_KEY"`
	CACert      string `env:"TLS_CA_CERT"`
	ClientCert  string `env:"TLS_CLIENT_CERT"`
	ClientKey   string `env:"TLS_CLIENT_KEY"`
	MTLSEnabled bool   `env:"MTLS_ENABLED" envDefault:"false"`
}

type JWTConfig struct {
	PrivateKey         string        `env:"JWT_PRIVATE_KEY"`
	PublicKey          string        `env:"JWT_PUBLIC_KEY"`
	AccessTokenExpiry  time.Duration `env:"JWT_ACCESS_TOKEN_EXPIRY"`
	RefreshTokenExpiry time.Duration `env:"JWT_REFRESH_TOKEN_EXPIRY"`
}

type OTPConfig struct {
	CodeLength                int           `env:"OTP_CODE_LENGTH"      envDefault:"6"`
	CodeTTL                   time.Duration `env:"OTP_CODE_TTL"         envDefault:"2m"`
	CodeSendLimit             int           `env:"OTP_SEND_LIMIT"       envDefault:"2"`
	CodeSendPeriod            time.Duration `env:"OTP_SEND_PERIOD"      envDefault:"10m"`
	CodeSendBlockTime         time.Duration `env:"OTP_SEND_BLOCK_TIME"  envDefault:"15m"`
	CodeCheckLimit            int           `env:"OTP_CHECK_LIMIT"      envDefault:"3"`
	CodeCheckPeriod           time.Duration `env:"OTP_CHECK_PERIOD"     envDefault:"10m"`
	CodeCheckBlockTime        time.Duration `env:"OTP_CHECK_BLOCK_TIME" envDefault:"60m"`
	SupportLink               string        `env:"SUPPORT_LINK"`
	JobDeleteCodeInterval     time.Duration `env:"JOB_DELETE_CODE_INTERVAL" envDefault:"1h"`
	RefreshTokenExpireSeconds int           `env:"REFRESH_TOKEN_EXPIRE_SECONDS" envDefault:"2592000"`
	TokenCleanupInterval      time.Duration `env:"TOKEN_CLEANUP_INTERVAL" envDefault:"720h"`
}

type SberIDConfig struct {
	BaseURL       string        `env:"SBER_ID_BASE_URL"`
	TokenURL      string        `env:"SBER_ID_TOKEN_URL"`
	UserInfoURL   string        `env:"SBER_ID_USERINFO_URL"`
	ClientID      string        `env:"SBER_ID_CLIENT_ID"`
	ClientSecret  string        `env:"SBER_ID_CLIENT_SECRET"`
	RedirectURI   string        `env:"SBER_ID_REDIRECT_URI"`
	Scope         string        `env:"SBER_ID_SCOPE" envDefault:"openid email mobile name"`
	Timeout       time.Duration `env:"SBER_ID_TIMEOUT" envDefault:"10s"`
	RetryAttempts int           `env:"SBER_ID_RETRY_ATTEMPTS" envDefault:"3"`

	CACert     string `env:"SBER_ID_CA_CERT"`
	ClientCert string `env:"SBER_ID_CLIENT_CERT"`
	ClientKey  string `env:"SBER_ID_CLIENT_KEY"`
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

	// Sber ID mTLS сертификаты всегда обязательны
	requiredFiles = append(requiredFiles,
		struct{ name, val string }{"SBER_ID_CA_CERT", c.SberID.CACert},
	)

	if c.SberID.ClientCert != "" && c.SberID.ClientKey != "" {
		requiredFiles = append(requiredFiles,
			struct{ name, val string }{"SBER_ID_CLIENT_CERT", c.SberID.ClientCert},
			struct{ name, val string }{"SBER_ID_CLIENT_KEY", c.SberID.ClientKey},
		)
	}

	for _, path := range requiredFiles {
		if path.val == "" {
			continue
		}

		if _, err := os.Stat(path.val); os.IsNotExist(err) {
			return Config{}, fmt.Errorf("missing TLS file for %s: %s", path.name, path.val)
		}
	}

	return c, nil
}
