package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/samandr77/microservices/payment/internal/api"
	"github.com/samandr77/microservices/payment/internal/clients/_1c"
	"github.com/samandr77/microservices/payment/internal/clients/auth"
	"github.com/samandr77/microservices/payment/internal/clients/client"
	"github.com/samandr77/microservices/payment/internal/clients/vtbbank"
	"github.com/samandr77/microservices/payment/internal/repository"
	"github.com/samandr77/microservices/payment/internal/service"
	"github.com/samandr77/microservices/payment/pkg/broker"
	"github.com/samandr77/microservices/payment/pkg/config"
	"github.com/samandr77/microservices/payment/pkg/job"
	"github.com/samandr77/microservices/payment/pkg/logger"
	"github.com/samandr77/microservices/payment/pkg/postgres"
	"github.com/samandr77/microservices/payment/pkg/security"
)

const (
	ReadTimeout  = 3 * time.Second
	WriteTimeout = 2 * time.Second
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.New(".env")
	panicOnErr("load config", err)

	_, err = logger.New(cfg.Logger.Level)
	panicOnErr("create logger", err)

	pool, err := postgres.Connect(ctx, cfg.Postgres.DSN, cfg.Postgres.MaxConn)
	panicOnErr("connect to postgres", err)
	defer pool.Close()

	err = postgres.UpMigrations(pool)
	panicOnErr("up migrations", err)

	repo := repository.New(pool)

	clientService := client.NewClient(cfg.ClientServiceURL)
	_1CService := _1c.NewClient(cfg.OneCServiceURL)

	producer := broker.NewProducer(cfg.Kafka.Brokers, cfg.Kafka.BalanceUpdatedTopic)
	defer producer.Close()

	vtbClient := vtbbank.NewClient(cfg.VTBBank)

	s := service.New(repo, clientService, _1CService, producer, vtbClient)

	authService := auth.NewClient(cfg.AuthServiceURL)

	{
		job.NewService().
			RegisterJob("update SPB payments status", time.Hour, s.UpdateSPBPaymentStatus).
			RegisterJob("update CARD payments status", time.Hour, s.UpdateCardPaymentStatus).
			RegisterJob("fail old payments", time.Hour, s.FailOldPayments).
			Start(ctx)
	}

	decodedPKey, err := base64.StdEncoding.DecodeString(cfg.VTBBank.CardCallbackPublicKey)
	panicOnErr("decode card callback public key", err)

	cardCallbackPublicKey, err := security.ParsePublicKey(decodedPKey)
	panicOnErr("parse card callback public key", err)

	handler := api.NewHandler(s, cfg.VTBBank.CardCallbackCheckEnabled, cardCallbackPublicKey)
	mw := api.NewMiddleware(authService, cfg.HTTP.APIKeyEnabled, cfg.HTTP.APIKey, cfg.VTBBank.CallbackIPWL)

	router := api.NewRouter(handler, mw)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTP.Port),
		Handler:      router,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
	}

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Panicf("listen and serve: %s", err)
		}
	}()

	slog.InfoContext(ctx, "service started", "port", cfg.HTTP.Port)

	wg.Add(1)

	go func() {
		defer wg.Done()

		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
		sig := <-ch

		slog.InfoContext(ctx, "got OS signal", "signal", sig.String())

		err = server.Shutdown(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "server shutdown", "error", err)
		}
	}()

	wg.Wait()
}

func panicOnErr(msg string, err error) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}
