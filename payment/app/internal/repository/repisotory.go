package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/samandr77/microservices/payment/internal/entity"
)

type Repository struct {
	db *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{
		db: pool,
	}
}

func (r *Repository) Transaction(ctx context.Context, id uuid.UUID) (entity.Transaction, error) {
	q := selectTx + " WHERE id = $1"
	return scanTx(r.db.QueryRow(ctx, q, id))
}

func (r *Repository) UpdateTransactionStatus(
	ctx context.Context,
	id uuid.UUID,
	status entity.TransactionStatus,
	updatedAt time.Time,
) error {
	const q = `UPDATE transactions SET status = $1, updated_at = $2 WHERE id = $3`

	result, err := r.db.Exec(ctx, q, status, updatedAt, id)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return entity.ErrNotFound
	}

	return nil
}

func (r *Repository) CreateTransaction(ctx context.Context, tx entity.Transaction) (entity.Transaction, error) {
	const q = `
	INSERT INTO transactions (
		id,
		name,
		client_id,
		client_guid,
		amount,
		payment_method,
		status,
		qrc_id,
	    invoice_url,
		created_by,
		created_at,
		updated_at
	)
	VALUES ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	RETURNING number
	`

	err := r.db.QueryRow(
		ctx,
		q,
		tx.ID,
		tx.Name,
		tx.ClientID,
		tx.ClientGUID,
		tx.Amount,
		tx.PaymentMethod,
		tx.Status,
		zeronull.Text(tx.QRCID),
		zeronull.Text(tx.InvoiceURL),
		tx.CreatedBy,
		tx.CreatedAt,
		tx.UpdatedAt,
	).Scan(&tx.Number)
	if err != nil {
		return entity.Transaction{}, err
	}

	return tx, nil
}

func (r *Repository) UpdateTransactionQRCID(ctx context.Context, id uuid.UUID, qrcid string, updatedAt time.Time) error {
	const q = `UPDATE transactions SET qrc_id = $1, updated_at = $2 WHERE id = $3`

	result, err := r.db.Exec(ctx, q, qrcid, updatedAt, id)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return entity.ErrNotFound
	}

	return nil
}

func (r *Repository) UpdateTransactionOrderID(ctx context.Context, id uuid.UUID, orderID uuid.UUID, updatedAt time.Time) error {
	const q = `UPDATE transactions SET order_id = $1, updated_at = $2 WHERE id = $3`

	result, err := r.db.Exec(ctx, q, orderID, updatedAt, id)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return entity.ErrNotFound
	}

	return nil
}

func (r *Repository) NotPaidTransactions(ctx context.Context, paymentMethod entity.PaymentMethod) (txs []entity.Transaction, err error) {
	q := selectTx + " WHERE status = $1 AND payment_method = $2"

	rows, err := r.db.Query(ctx, q, entity.TransactionStatusCreated, paymentMethod)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		tx, err := scanTx(rows)
		if err != nil {
			return nil, err
		}

		txs = append(txs, tx)
	}

	return txs, nil
}

func (r *Repository) TransactionByGUID(ctx context.Context, clientGUID uuid.UUID, number int64) (tx entity.Transaction, err error) {
	q := selectTx + " WHERE client_guid = $1 AND number = $2"
	return scanTx(r.db.QueryRow(ctx, q, clientGUID, number))
}

func (r *Repository) Transactions(
	ctx context.Context,
	clientID uuid.UUID,
	f entity.TransactionFilter,
) ([]entity.Transaction, int, error) {
	stmt := sq.Select(
		"id",
		"name",
		"number",
		"client_id",
		"client_guid",
		"amount",
		"payment_method",
		"status",
		"qrc_id",
		"invoice_url",
		"created_by",
		"created_at",
		"updated_at",
		"COUNT(*) OVER() AS total_count",
	).From("transactions").Where(sq.Eq{"client_id": clientID}).PlaceholderFormat(sq.Dollar)

	stmt = applyTransactionFilter(stmt, f).
		Limit(f.Limit).
		Offset(f.Page*f.Limit - f.Limit).
		OrderBy(fmt.Sprintf("%s %s", f.SortBy, f.OrderBy))

	sql, args, err := stmt.ToSql()
	if err != nil {
		return nil, 0, err
	}

	rows, err := r.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	transactions := make([]entity.Transaction, 0, f.Limit)

	var totalCount int

	for rows.Next() {
		var tx entity.Transaction

		var count int

		err = rows.Scan(
			&tx.ID,
			&tx.Name,
			&tx.Number,
			&tx.ClientID,
			&tx.ClientGUID,
			&tx.Amount,
			&tx.PaymentMethod,
			&tx.Status,
			(*zeronull.Text)(&tx.QRCID),
			(*zeronull.Text)(&tx.InvoiceURL),
			&tx.CreatedBy,
			&tx.CreatedAt,
			&tx.UpdatedAt,
			&count,
		)
		if err != nil {
			return nil, 0, err
		}

		totalCount = count

		transactions = append(transactions, tx)
	}

	return transactions, totalCount, nil
}

func applyTransactionFilter(stmt sq.SelectBuilder, f entity.TransactionFilter) sq.SelectBuilder {
	if f.ID != nil {
		stmt = stmt.Where(sq.Eq{"id": *f.ID})
	}

	if f.Amount != nil {
		stmt = stmt.Where(sq.Eq{"amount": *f.Amount})
	}

	if f.CreatedAt != nil {
		stmt = stmt.Where(sq.GtOrEq{"created_at": *f.CreatedAt})
	}

	return stmt
}

func scanTx(row pgx.Row) (tx entity.Transaction, err error) {
	err = row.Scan(
		&tx.ID,
		&tx.Name,
		&tx.Number,
		&tx.ClientID,
		&tx.ClientGUID,
		&tx.Amount,
		&tx.PaymentMethod,
		&tx.Status,
		(*zeronull.Text)(&tx.QRCID),
		(*zeronull.Text)(&tx.InvoiceURL),
		&tx.CreatedBy,
		&tx.CreatedAt,
		&tx.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.Transaction{}, entity.ErrNotFound
		}

		return entity.Transaction{}, err
	}

	return tx, nil
}

func (r *Repository) SaveInvoiceURL(ctx context.Context, billNumber int64, url string, updatedAt time.Time) error {
	const q = `UPDATE transactions SET invoice_url = $1, updated_at = $2 WHERE number = $3`

	result, err := r.db.Exec(ctx, q, url, updatedAt, billNumber)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return entity.ErrNotFound
	}

	return nil
}

func (r *Repository) SetStatus(ctx context.Context, prevStatus, status entity.TransactionStatus, createdAtFrom time.Time) error {
	q := `UPDATE transactions SET status = $1 WHERE status = $2 AND created_at < $3`

	_, err := r.db.Exec(ctx, q, status, prevStatus, createdAtFrom)
	if err != nil {
		return err
	}

	return nil
}
