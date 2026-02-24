package repository

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

var (
	testDB     *pgxpool.Pool
	testDBOnce sync.Once
)

func SetupTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()

	testDBOnce.Do(func() {
		dsn := os.Getenv("TEST_POSTGRES_DSN")
		if dsn == "" {
			dsn = "postgres://postgres:dev@localhost:15432/postgres?sslmode=disable"
		}

		db, err := pgxpool.New(context.Background(), dsn)
		require.NoError(t, err)

		testDB = db
	})

	CleanupDatabase(t, testDB)

	return testDB
}

func CleanupDatabase(t *testing.T, db *pgxpool.Pool) {
	t.Helper()

	ctx := context.Background()

	tables := []string{
		"token",
		"attempts_blocks",
		"attempts",
		"verification_codes",
	}

	for _, table := range tables {
		_, err := db.Exec(ctx, "DELETE FROM "+table)
		if err != nil {
			t.Logf("Warning: failed to cleanup table %s: %v", table, err)
		}
	}
}
