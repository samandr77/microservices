package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/samandr77/microservices/notification/internal/api"
	"github.com/samandr77/microservices/notification/internal/api/events"
	"github.com/samandr77/microservices/notification/internal/clients/gomail"
	"github.com/samandr77/microservices/notification/internal/service"
	"github.com/samandr77/microservices/notification/pkg/broker"
	"github.com/samandr77/microservices/notification/pkg/config"
	"github.com/samandr77/microservices/notification/pkg/logger"
)

const (
	readTimeout       = 3 * time.Second
	readHeaderTimeout = time.Second
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.New(".env")
	panicOnErr("create config", err)

	l := logger.New(slog.LevelDebug)

	gomailClient := gomail.New(cfg)
	s := service.New(cfg, gomailClient)

	// Kafka consumers
	{
		consumer := broker.NewConsumer(l, cfg.Kafka.Brokers, cfg.Kafka.ConsumerID, []string{cfg.Kafka.NotificationTopic})
		defer consumer.Close()

		eventHandler := events.NewEventHandler(s)

		consumer.Handle(cfg.Kafka.NotificationTopic, eventHandler.SendVerificationCode)
		consumer.Consume(ctx)
	}

	h := api.NewHandler(s)
	mw := api.NewMiddleware(l)

	router := api.NewRouter(h, mw)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           router,
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.MTLSEnabled {
		caCert, err := os.ReadFile(cfg.CACert)
		panicOnErr("load CA cert", err)

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Panic("failed to append CA cert to pool")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	server.TLSConfig = tlsConfig

	go func() {
		err := server.ListenAndServeTLS(cfg.ServerCert, cfg.ServerKey)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Panic(err)
		}
	}()

	l.Info("server started", "port", cfg.HTTPPort)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)
	sig := <-ch

	l.Info("got OS signal", "signal", sig.String())

	err = server.Shutdown(ctx)
	if err != nil {
		l.Error("shutdown", "error", err)
	}
}

func panicOnErr(msg string, err error) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}
