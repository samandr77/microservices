package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/samandr77/microservices/client/internal/api"
	"github.com/samandr77/microservices/client/internal/clients/auth"
	"github.com/samandr77/microservices/client/internal/repository"
	"github.com/samandr77/microservices/client/internal/service"
	"github.com/samandr77/microservices/client/pkg/config"
	"github.com/samandr77/microservices/client/pkg/logger"
	"github.com/samandr77/microservices/client/pkg/postgres"
)

const (
	ReadTimeout       = 3 * time.Second
	WriteTimeout      = 2 * time.Second
	IdleTimeout       = 60 * time.Second
	ReadHeaderTimeout = 1 * time.Second
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.New(".env")
	panicOnErr(ctx, "load config", err)

	l := logger.New(logger.ParseLevel(cfg.LogLevel))
	slog.SetDefault(l)

	pool, err := postgres.ConnectToPostgres(ctx, cfg.PostgresDSN, cfg.PostgresMaxConns)
	panicOnErr(ctx, "connect to postgres", err)

	defer pool.Close()

	err = postgres.UpMigrations(cfg.PostgresDSN)
	panicOnErr(ctx, "up migrations", err)

	userRepo := repository.NewUserRepository(pool)
	roleRepo := repository.NewRoleRepository(pool)
	userBlockRepo := repository.NewUserBlockRepository(pool)

	authClient := auth.NewClient(cfg.AuthServiceURL, cfg)

	s := service.NewService(&cfg, userRepo, roleRepo, userBlockRepo, authClient)

	h := api.NewHandler(s)
	mw := api.NewMiddleware(authClient, cfg, s)
	router := api.NewRouter(h, mw)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           router,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		ReadHeaderTimeout: ReadHeaderTimeout,
	}

	tlsConfig := configureTLS(ctx, &cfg)
	server.TLSConfig = tlsConfig

	var wg sync.WaitGroup

	startHTTPServer(&wg, l, server, &cfg)
	startProcessExpiredBlocksJob(ctx, &wg, l, s, &cfg)
	startCleanupExpiredDeletedAccountsJob(ctx, &wg, l, s, &cfg)

	waitSignal(l, cancel, server)
	wg.Wait()
}

func startHTTPServer(wg *sync.WaitGroup, l *slog.Logger, server *http.Server, cfg *config.Config) {
	wg.Add(1)

	go func() {
		defer wg.Done()

		l.Info("http server started", "port", cfg.HTTPPort, "mtls", cfg.MTLSEnabled)

		err := server.ListenAndServeTLS(cfg.ServerCert, cfg.ServerKey)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.Error("Failed to listen and serve TLS", "error", err, "port", cfg.HTTPPort)
			panic(fmt.Sprintf("listen and serve TLS: %s", err))
		}

		l.Debug("http server stopped")
	}()
}

func startBackgroundJob(
	ctx context.Context,
	wg *sync.WaitGroup,
	l *slog.Logger,
	jobName string,
	interval time.Duration,
	jobFunc func(ctx context.Context) error,
) {
	wg.Add(1)

	go func() {
		defer wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		jobLogger := l.With("job", jobName)
		for {
			jobLogger.Debug("job started")

			err := jobFunc(ctx)
			if err != nil {
				jobLogger.Error(fmt.Sprintf("job failed: %s", err))
			} else {
				jobLogger.Debug("job finished")
			}

			select {
			case <-ctx.Done():
				jobLogger.Debug("job stopped by ctx")
				return
			case <-ticker.C:
			}
		}
	}()
}

func startProcessExpiredBlocksJob(
	ctx context.Context,
	wg *sync.WaitGroup,
	l *slog.Logger,
	s interface {
		ProcessExpiredTemporaryBlocks(ctx context.Context) error
	},
	cfg *config.Config,
) {
	blockCheckInterval := time.Duration(cfg.UserService.BlockCheckIntervalMinutes) * time.Minute
	startBackgroundJob(ctx, wg, l, "process_expired_blocks", blockCheckInterval, s.ProcessExpiredTemporaryBlocks)
}

func startCleanupExpiredDeletedAccountsJob(
	ctx context.Context,
	wg *sync.WaitGroup,
	l *slog.Logger,
	s interface {
		CleanupExpiredDeletedAccounts(ctx context.Context) error
	},
	cfg *config.Config,
) {
	cleanupInterval := time.Duration(cfg.UserService.DeletedAccountsCleanupInterval) * time.Hour
	startBackgroundJob(ctx, wg, l, "cleanup_expired_deleted_accounts", cleanupInterval, s.CleanupExpiredDeletedAccounts)
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

func panicOnErr(ctx context.Context, msg string, err error) {
	if err != nil {
		slog.ErrorContext(ctx, "Fatal error", "message", msg, "error", err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

func configureTLS(ctx context.Context, cfg *config.Config) *tls.Config {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.MTLSEnabled {
		caCert, err := os.ReadFile(cfg.CACert)
		panicOnErr(ctx, "load CA cert", err)

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			slog.ErrorContext(ctx, "Failed to append CA cert to pool", "ca_cert_path", cfg.CACert)
			panic("failed to append CA cert to pool")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	return tlsConfig
}
