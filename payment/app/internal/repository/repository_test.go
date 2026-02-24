package repository_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"

	"github.com/samandr77/microservices/payment/internal/entity"
	"github.com/samandr77/microservices/payment/internal/repository"
	"github.com/samandr77/microservices/payment/pkg/postgres"
)

func TestRepository_CreateTransaction(t *testing.T) {
	t.Parallel()

	repo := newRepository(t)
	now := time.Now().Truncate(time.Millisecond)

	tx := entity.Transaction{
		ID:             uuid.Must(uuid.NewV4()),
		Name:           uuid.Must(uuid.NewV4()).String(),
		Number:         0, // Fill in by DB
		ClientID:       uuid.Must(uuid.NewV4()),
		ClientGUID:     uuid.Must(uuid.NewV4()),
		Amount:         decimal.New(1_000_000_000, -2),
		TaxRatePercent: 0, // Not stored in the DB
		PaymentMethod:  entity.PaymentMethodInvoice,
		Status:         entity.TransactionStatusCreated,
		QRCID:          uuid.Must(uuid.NewV4()).String(),
		InvoiceURL:     uuid.Must(uuid.NewV4()).String(),
		CreatedBy:      uuid.Must(uuid.NewV4()),
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err := repo.CreateTransaction(context.Background(), tx)
	require.NoError(t, err)
	require.NotEmpty(t, tx.Number)

	// Check that the transaction was created correctly.
	txGot, err := repo.Transaction(context.Background(), tx.ID)
	require.NoError(t, err)
	require.Equal(t, tx, txGot)
}

func TestRepository_SetStatus(t *testing.T) {
	t.Parallel()

	repo := newRepository(t)
	now := time.Now().Truncate(time.Millisecond)

	txs := []entity.Transaction{
		{
			ID:        uuid.Must(uuid.NewV4()),
			CreatedAt: now,
			Status:    entity.TransactionStatusCreated,
		},
		{
			ID:        uuid.Must(uuid.NewV4()),
			CreatedAt: now.Add(-time.Hour * 2),
			Status:    entity.TransactionStatusCreated,
		},
	}

	for _, tx := range txs {
		_, err := repo.CreateTransaction(context.Background(), tx)
		require.NoError(t, err)
	}

	err := repo.SetStatus(context.Background(), entity.TransactionStatusCreated, entity.TransactionStatusFailed, now.Add(-time.Hour))
	require.NoError(t, err)

	// Check that the status was not changed.
	txGot, err := repo.Transaction(context.Background(), txs[0].ID)
	require.NoError(t, err)
	require.Equal(t, entity.TransactionStatusCreated, txGot.Status)

	// Check that the status was changed correctly.
	txGot, err = repo.Transaction(context.Background(), txs[1].ID)
	require.NoError(t, err)
	require.Equal(t, entity.TransactionStatusFailed, txGot.Status)
}

func newRepository(t *testing.T) *repository.Repository {
	t.Helper()

	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://postgres:dev@localhost:15432/postgres"
	}

	pool, err := postgres.Connect(context.Background(), dsn, 10)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	repo := repository.New(pool)

	return repo
}
