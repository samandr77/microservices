package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/caarlos0/env/v7"
	"github.com/joho/godotenv"
)

type Config struct {
	HTTPPort int `env:"HTTP_PORT"`

	// SMTP
	MailerFrom       string `env:"MAILER_FROM"`
	MailerFromName   string `env:"MAILER_FROM_NAME"`
	MailerHost       string `env:"MAILER_HOST"`
	MailerPort       int    `env:"MAILER_PORT"`
	MailerLogin      string `env:"MAILER_LOGIN"`
	MailerPassword   string `env:"MAILER_PASSWORD"`
	MailerEncryption string `env:"MAILER_ENCRYPTION"`

	// Kafka
	Kafka Kafka

	// TLS / mTLS
	ServerCert  string `env:"TLS_SERVER_CERT"`
	ServerKey   string `env:"TLS_SERVER_KEY"`
	CACert      string `env:"TLS_CA_CERT"`
	ClientCert  string `env:"TLS_CLIENT_CERT"`
	ClientKey   string `env:"TLS_CLIENT_KEY"`
	MTLSEnabled bool   `env:"MTLS_ENABLED" envDefault:"false"`
}

type Kafka struct {
	Brokers           []string `env:"KAFKA_BROKERS" envDefault:"kafka:9092"`
	ConsumerID        string   `env:"KAFKA_CONSUMER_ID" envDefault:"notification"`
	NotificationTopic string   `env:"KAFKA_NOTIFICATION_TOPIC" envDefault:"send-notifications"`
}

func New(envPath string) (Config, error) {
	var c Config

	err := godotenv.Load(envPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	err = env.Parse(&c, env.Options{RequiredIfNoDef: true})
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
