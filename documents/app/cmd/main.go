package main

import (
	"context"
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

	"github.com/samandr77/microservices/documents/internal/api"
	"github.com/samandr77/microservices/documents/internal/api/events"
	"github.com/samandr77/microservices/documents/internal/httpclients/campaigns"
	"github.com/samandr77/microservices/documents/internal/httpclients/clients"
	"github.com/samandr77/microservices/documents/internal/httpclients/onec"
	"github.com/samandr77/microservices/documents/internal/httpclients/roback"
	"github.com/samandr77/microservices/documents/internal/httpclients/s3"
	"github.com/samandr77/microservices/documents/internal/repository"
	"github.com/samandr77/microservices/documents/internal/service"
	"github.com/samandr77/microservices/documents/pkg/broker"
	"github.com/samandr77/microservices/documents/pkg/config"
	"github.com/samandr77/microservices/documents/pkg/logger"
	"github.com/samandr77/microservices/documents/pkg/postgres"
)

const (
	ReadTimeout  = 20 * time.Second
	WriteTimeout = 20 * time.Second
)

//nolint:funlen
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.New(".env")
	panicOnErr("load config", err)

	_ = logger.New()

	pool, err := postgres.Connect(ctx, cfg.PostgresDSN, cfg.PostgresMaxConns)
	panicOnErr("connect to postgres", err)
	defer pool.Close()

	err = postgres.UpMigrations(cfg.PostgresDSN)
	panicOnErr("up migrations", err)

	repo := repository.New(pool)

	client := clients.NewClient(cfg.ClientsServiceURL)
	campaign := campaigns.NewClient(cfg.CampaignsServiceURL)
	oneC := onec.NewClient(cfg.OneCServiceURL)
	s3Client := s3.NewClient()

	panicOnErr("new s3 client", err)

	roBack := service.Roback(roback.NewClient(cfg.RoBackServiceURL, cfg.ProcessID))

	if cfg.MockRoBack {
		roBack = roback.NewMock()
	}

	s := service.New(client, campaign, roBack, oneC, s3Client, repo, cfg.OfertaS3URL)

	// Kafka consumers
	{
		consumer := broker.NewConsumer(cfg.Kafka.Brokers, cfg.Kafka.ConsumerID, cfg.Kafka.BalanceUpdatedTopic)
		defer consumer.Close()

		eventHandler := events.NewEventHandler(s)

		consumer.Handle(cfg.Kafka.BalanceUpdatedTopic, eventHandler.OnBalanceUpdated)
		consumer.Consume(ctx)
	}

	handler := api.NewHandler(s)
	mw := api.NewMiddleware(cfg)

	router := api.NewRouter(handler, mw)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      router,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
	}

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		slog.InfoContext(ctx, "http server started", "port", cfg.HTTPPort)

		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Panicf("listen and serve: %s", err)
		}

		slog.DebugContext(ctx, "http server stopped")
	}()

	wg.Add(1)

	go func() {
		defer wg.Done()

		ticker := time.NewTicker(cfg.JobSignDocsInterval)
		defer ticker.Stop()

		l := slog.Default().With("job", "sign_documents")
		for {
			l.Debug("job started")

			err := s.SignDocuments(ctx)
			if err != nil {
				l.ErrorContext(ctx, fmt.Sprintf("job failed: %s", err))
			} else {
				l.DebugContext(ctx, "job finished")
			}

			select {
			case <-ctx.Done():
				l.DebugContext(ctx, "job stopped by ctx")
				return
			case <-ticker.C:
			}
		}
	}()

	waitSignal(cancel, server)

	wg.Wait()
}

func waitSignal(cancel context.CancelFunc, server *http.Server) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	sig := <-ch

	slog.Info("got OS signal", "signal", sig.String())

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()

	err := server.Shutdown(shutdownCtx)
	if err != nil {
		slog.ErrorContext(shutdownCtx, "server shutdown", "error", err)
	}
}

func panicOnErr(msg string, err error) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}
