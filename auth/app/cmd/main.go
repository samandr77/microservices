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
	"sync"
	"syscall"
	"time"

	"github.com/samandr77/microservices/auth/internal/api"
	"github.com/samandr77/microservices/auth/internal/clients/sberid"
	"github.com/samandr77/microservices/auth/internal/clients/users"
	"github.com/samandr77/microservices/auth/internal/repository"
	"github.com/samandr77/microservices/auth/internal/service"
	"github.com/samandr77/microservices/auth/pkg/broker"
	"github.com/samandr77/microservices/auth/pkg/config"
	"github.com/samandr77/microservices/auth/pkg/logger"
	"github.com/samandr77/microservices/auth/pkg/postgres"
)

const (
	ReadTimeout       = 3 * time.Second
	WriteTimeout      = 2 * time.Second
	IdleTimeout       = 60 * time.Second
	ReadHeaderTimeout = 1 * time.Second
)

//nolint:funlen
func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.New(".env")
	panicOnErr("load config", err)

	l := logger.New(logger.ParseLevel(cfg.LogLevel))
	slog.SetDefault(l)

	pool, err := postgres.ConnectToPostgres(ctx, cfg.PostgresDSN, cfg.PostgresMaxConns)
	panicOnErr("connect to postgres", err)

	defer pool.Close()

	err = postgres.UpMigrations(cfg.PostgresDSN)
	panicOnErr("up migrations", err)

	codeRepo := repository.NewCodeRepository(pool)
	refreshTokenRepo := repository.NewRefreshTokenRepository(pool)
	attemptRepo := repository.NewAttemptRepository(pool)
	usersClient := users.NewClient(cfg.UserServiceURL, cfg)

	sberIDClient := sberid.NewClient(cfg)

	producer := broker.NewProducer(l, cfg.KafkaBrokers, cfg.KafkaTopic)
	defer producer.Close()

	s := service.NewService(cfg, codeRepo, refreshTokenRepo, attemptRepo, producer, usersClient, sberIDClient)

	h := api.NewHandler(s, cfg.OTP.SupportLink, cfg.SberID.ClientID, cfg.SberID.RedirectURI, cfg.SberID.Scope, cfg.SberID.BaseURL)
	mw := api.NewMiddleware(s)
	router := api.NewRouter(h, mw)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           router,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		ReadHeaderTimeout: ReadHeaderTimeout,
	}

	tlsConfig := configureTLS(&cfg)
	server.TLSConfig = tlsConfig

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		l.Info("http server started", "port", cfg.HTTPPort, "mtls", cfg.MTLSEnabled)

		err := server.ListenAndServeTLS(cfg.ServerCert, cfg.ServerKey)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Panicf("listen and serve TLS: %s", err)
		}

		l.Debug("http server stopped")
	}()
	wg.Add(1)

	go func() {
		defer wg.Done()

		ticker := time.NewTicker(cfg.OTP.JobDeleteCodeInterval)
		defer ticker.Stop()

		l := l.With("job", "delete_code")
		for {
			l.Debug("job started")

			err := s.DeleteExpiredCode(ctx)
			if err != nil {
				l.Error(fmt.Sprintf("job failed: %s", err))
			} else {
				l.Debug("job finished")
			}

			select {
			case <-ctx.Done():
				l.Debug("job stopped by ctx")
				return
			case <-ticker.C:
			}
		}
	}()

	wg.Add(1)

	go func() {
		defer wg.Done()

		ticker := time.NewTicker(cfg.OTP.TokenCleanupInterval)
		defer ticker.Stop()

		l := l.With("job", "delete_refresh_tokens")
		for {
			l.Debug("job started")

			err := s.DeleteExpiredTokens(ctx)
			if err != nil {
				l.Error(fmt.Sprintf("job failed: %s", err))
			} else {
				l.Debug("job finished")
			}

			select {
			case <-ctx.Done():
				l.Debug("job stopped by ctx")
				return
			case <-ticker.C:
			}
		}
	}()

	waitSignal(l, cancel, server)
	wg.Wait()
}

func waitSignal(l *slog.Logger, cancel context.CancelFunc, server *http.Server) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	sig := <-ch

	l.Info("got OS signal", "signal", sig.String())

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()

	err := server.Shutdown(shutdownCtx)
	if err != nil {
		l.Error("server shutdown", "error", err)
	}
}

func panicOnErr(msg string, err error) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

func configureTLS(cfg *config.Config) *tls.Config {
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

	return tlsConfig
}
