package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/samandr77/microservices/auth/migrations"

	_ "github.com/jackc/pgx/v5/stdlib" //nolint:blank-imports

	goose "github.com/pressly/goose/v3"
)

func ConnectToPostgres(ctx context.Context, dsn string, maxConn int32) (*pgxpool.Pool, error) {
	dbCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	dbCfg.MaxConns = maxConn

	pool, err := pgxpool.NewWithConfig(ctx, dbCfg)
	if err != nil {
		return nil, fmt.Errorf("create db pool: %w", err)
	}

	const timeout = 500 * time.Millisecond

	for range 10 {
		err = pool.Ping(ctx)
		if err == nil {
			return pool, nil
		}

		time.Sleep(timeout)
	}

	return nil, fmt.Errorf("ping: %w", err)
}

func UpMigrations(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}

	fs := migrations.FS
	goose.SetBaseFS(fs)
	goose.SetLogger(goose.NopLogger())

	err = goose.SetDialect("postgres")
	if err != nil {
		return err
	}

	err = goose.Up(db, ".")
	if err != nil && !errors.Is(err, goose.ErrNoNextVersion) {
		return err
	}

	return nil
}
