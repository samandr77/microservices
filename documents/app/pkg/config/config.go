package config

import (
	"errors"
	"os"
	"time"

	"github.com/caarlos0/env/v7"
	"github.com/joho/godotenv"
)

type Config struct {
	HTTPPort               int           `env:"HTTP_PORT"`
	PostgresDSN            string        `env:"POSTGRES_DSN"`
	PostgresMaxConns       int32         `env:"POSTGRES_MAX_CONNS"`
	ClientsServiceURL      string        `env:"CLIENTS_SERVICE_URL"`
	CampaignsServiceURL    string        `env:"CAMPAIGNS_SERVICE_URL"`
	RoBackServiceURL       string        `env:"RO_BACK_SERVICE_URL"`
	OneCServiceURL         string        `env:"ONE_C_SERVICE_URL"`
	OneCVerificationPeriod time.Duration `env:"ONE_C_VERIFICATION_PERIOD"`
	AuthServiceURL         string        `env:"AUTH_SERVICE_URL"`
	JobSignDocsInterval    time.Duration `env:"JOB_SIGN_DOCS_INTERVAL" envDefault:"1h"`
	ProcessID              string        `env:"PROCESS_ID"`
	MockRoBack             bool          `env:"MOCK_RO_BACK" envDefault:"true"`
	OfertaS3URL            string        `env:"OFERTA_S3_URL"`
	Kafka                  Kafka
}

type Kafka struct {
	Brokers             []string `env:"KAFKA_BROKERS"`
	ConsumerID          string   `env:"KAFKA_CONSUMER_ID"`
	BalanceUpdatedTopic string   `env:"KAFKA_BALANCE_UPDATED_TOPIC"`
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

	return c, nil
}
