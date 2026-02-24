package repository_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
	"github.com/samandr77/microservices/documents/internal/entity"
	"github.com/samandr77/microservices/documents/internal/repository"
	"github.com/samandr77/microservices/documents/pkg/postgres"
)

func TestRepository_DocumentByClientID(t *testing.T) {
	t.Parallel()

	repo := repository.New(dbPool(t))

	now := time.Now().Truncate(time.Millisecond)
	sum := decimal.RequireFromString("1234.56")

	want := entity.Document{
		ID:         uuid.Must(uuid.NewV4()),
		ClientID:   uuid.Must(uuid.NewV4()),
		ClientName: uuid.Must(uuid.NewV4()).String(),
		Name:       uuid.Must(uuid.NewV4()).String(),
		DocType:    entity.DocTypeOferta,
		Status:     entity.DocStatusCreated,
		CreatedAt:  now,
		SignedAt:   &now,
		Sum:        &sum,
		URL:        uuid.Must(uuid.NewV4()).String(),
		Data: entity.ClosingDocumentsData{
			ActInfo: entity.ActInfo{
				ActNumber: uuid.Must(uuid.NewV4()).String(),
				ActDate:   now,
			},
			InvoiceInfo: entity.InvoiceInfo{
				InvoiceNumber: uuid.Must(uuid.NewV4()).String(),
				InvoiceDate:   now,
			},
			Occassion: uuid.Must(uuid.NewV4()).String(),
			ServicesList: []entity.ServicesList{
				{
					Name:        uuid.Must(uuid.NewV4()).String(),
					Amount:      uuid.Must(uuid.NewV4()).String(),
					Units:       uuid.Must(uuid.NewV4()).String(),
					UnitPrice:   decimal.RequireFromString("1000.25"),
					TaxRate:     uuid.Must(uuid.NewV4()).String(),
					TaxAmount:   decimal.RequireFromString("123.45"),
					TotalAmount: decimal.RequireFromString("12345.67"),
				},
			},
		},
		OneCGuid: uuid.Must(uuid.NewV4()),
	}

	err := repo.CreateDocuments(context.Background(), want)
	require.NoError(t, err)

	got, err := repo.DocumentByID(context.Background(), want.ID)
	require.NoError(t, err)
	require.Equal(t, want, got)

	got, err = repo.DocumentByClientID(context.Background(), want.ClientID)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func dbPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool, err := postgres.Connect(context.Background(), os.Getenv("TEST_POSTGRES_DSN"), 10)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return pool
}
