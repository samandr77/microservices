package config

import (
	"errors"
	"os"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	HTTP             HTTP
	Logger           Logger
	Postgres         Postgres
	AuthServiceURL   string `env:"AUTH_SERVICE_URL"`
	UserServiceURL   string `env:"USERS_SERVICE_URL"`
	ClientServiceURL string `env:"CLIENTS_SERVICE_URL"`
	OneCServiceURL   string `env:"_1C_SERVICE_URL"`
	Kafka            Kafka
	VTBBank          VTBBank
}

type HTTP struct {
	Port          int    `env:"HTTP_PORT" envDefault:"8080"`
	APIKeyEnabled bool   `env:"HTTP_API_KEY_ENABLED" envDefault:"false"`
	APIKey        string `env:"HTTP_API_KEY" envDefault:"dev"`
}

type Logger struct {
	Level  string `env:"LOG_LEVEL" envDefault:"info"`
	Format string `env:"LOG_FORMAT" envDefault:"json"`
}

type Postgres struct {
	DSN     string `env:"POSTGRES_DSN"`
	MaxConn int32  `env:"POSTGRES_MAX_CONNS" envDefault:"10"`
}

type Kafka struct {
	Brokers             []string `env:"KAFKA_BROKERS"`
	BalanceUpdatedTopic string   `env:"KAFKA_BALANCE_UPDATED_TOPIC"`
}

type VTBBank struct {
	BaseURL                  string   `env:"VTB_BANK_BASE_URL"`
	ClientID                 string   `env:"VTB_BANK_CLIENT_ID"`
	ClientSecret             string   `env:"VTB_BANK_CLIENT_SECRET"`
	SPBRedirectURL           string   `env:"VTB_BANK_SPB_REDIRECT_URL"`
	CallbackIPWL             []string `env:"VTB_BANK_CALLBACK_IP_WL"`
	CardPaymentURL           string   `env:"VTB_BANK_CARD_PAYMENT_URL"`
	CardPaymentLogin         string   `env:"VTB_BANK_CARD_PAYMENT_LOGIN"`
	CardPaymentPassword      string   `env:"VTB_BANK_CARD_PAYMENT_PASSWORD"`
	CardRedirectURL          string   `env:"VTB_BANK_CARD_REDIRECT_URL"`
	CardCallbackCheckEnabled bool     `env:"VTB_BANK_CARD_CALLBACK_CHECK_ENABLED" envDefault:"false"`
	CardCallbackPublicKey    string   `env:"VTB_BANK_CARD_CALLBACK_PUBLIC_KEY"` // PEM encoded
}

func New(envPath string) (Config, error) {
	err := godotenv.Load(envPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	c, err := env.ParseAsWithOptions[Config](env.Options{
		RequiredIfNoDef: true,
	})
	if err != nil {
		return Config{}, err
	}

	return c, nil
}
