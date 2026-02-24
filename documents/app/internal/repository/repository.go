package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/samandr77/microservices/documents/internal/entity"
)

type Repository struct {
	db *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{
		db: pool,
	}
}

func (r *Repository) DocumentByClientIDAndType(
	ctx context.Context, clientID uuid.UUID, documentType entity.DocType) (entity.Document, error) {
	sqlQuery :=
		`SELECT id, client_id, client_name, name, doc_type, status, created_at, signed_at, sum, url, data, one_c_guid
		FROM documents
		WHERE client_id = $1 AND doc_type = $2`

	var document entity.Document

	err := r.db.QueryRow(ctx, sqlQuery, clientID, documentType).Scan(
		&document.ID,
		&document.ClientID,
		&document.ClientName,
		&document.Name,
		&document.DocType,
		&document.Status,
		&document.CreatedAt,
		&document.SignedAt,
		&document.Sum,
		&document.URL,
		&document.Data,
		&document.OneCGuid,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.Document{}, entity.ErrNotFound
		}

		return entity.Document{}, err
	}

	return document, nil
}

func (r *Repository) SignOferta(ctx context.Context, clientID uuid.UUID, signedAt time.Time) error {
	sqlQuery :=
		`UPDATE documents
		SET status = $1, signed_at = $2
		WHERE client_id = $3 AND doc_type = $4`

	_, err := r.db.Exec(ctx, sqlQuery,
		entity.DocStatusSigned,
		signedAt,
		clientID,
		entity.DocTypeOferta,
	)

	if err != nil {
		return err
	}

	return nil
}

func (r *Repository) DocumentsListByFilter(ctx context.Context, filter entity.DocumentsFilter) ([]entity.Document, int, error) {
	stmt := sq.Select("count(*)").From("documents").Where(sq.Eq{"client_id": filter.ClientID}).PlaceholderFormat(sq.Dollar)

	sqlQuery, args, err := stmt.ToSql()
	if err != nil {
		return nil, 0, err
	}

	var count int

	err = r.db.QueryRow(ctx, sqlQuery, args...).Scan(&count)
	if err != nil {
		return nil, 0, err
	}

	if count == 0 {
		return nil, 0, entity.ErrNotFound
	}

	stmt = sq.Select(
		"id",
		"client_id",
		"client_name",
		"name",
		"doc_type",
		"status",
		"created_at",
		"signed_at",
		"sum",
		"url",
		"data",
		"one_c_guid",
	).From("documents").PlaceholderFormat(sq.Dollar)

	stmt = applyDocumentsFilter(stmt, filter)

	sqlQuery, args, err = stmt.ToSql()
	if err != nil {
		return nil, 0, err
	}

	rows, err := r.db.Query(ctx, sqlQuery, args...)
	if err != nil {
		return nil, 0, err
	}

	defer rows.Close()

	documents := make([]entity.Document, 0, filter.Limit)

	for rows.Next() {
		var document entity.Document

		err = rows.Scan(
			&document.ID,
			&document.ClientID,
			&document.ClientName,
			&document.Name,
			&document.DocType,
			&document.Status,
			&document.CreatedAt,
			&document.SignedAt,
			&document.Sum,
			&document.URL,
			&document.Data,
			&document.OneCGuid,
		)

		if err != nil {
			return nil, 0, err
		}

		documents = append(documents, document)
	}

	return documents, count, nil
}

func applyDocumentsFilter(stmt sq.SelectBuilder, filter entity.DocumentsFilter) sq.SelectBuilder {
	stmt = stmt.Where(sq.Eq{"client_id": filter.ClientID})

	stmt = stmt.Limit(filter.Limit)
	stmt = stmt.Offset((filter.Page - 1) * filter.Limit)
	stmt = stmt.OrderBy(fmt.Sprintf("%s %s", filter.SortBy, filter.OrderBy))

	return stmt
}

func (r *Repository) DocumentByID(ctx context.Context, documentID uuid.UUID) (entity.Document, error) {
	sqlQuery := `
		SELECT id, client_id, client_name, name, doc_type, status, created_at, signed_at, sum, url, data, one_c_guid
		FROM documents
		WHERE id = $1`

	var document entity.Document

	err := r.db.QueryRow(ctx, sqlQuery, documentID).Scan(
		&document.ID,
		&document.ClientID,
		&document.ClientName,
		&document.Name,
		&document.DocType,
		&document.Status,
		&document.CreatedAt,
		&document.SignedAt,
		&document.Sum,
		&document.URL,
		&document.Data,
		&document.OneCGuid,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.Document{}, entity.ErrNotFound
		}

		return entity.Document{}, err
	}

	return document, nil
}

func (r *Repository) SaveClosingDocumentsRequest(ctx context.Context, req entity.ClosingDocumentsRequest) error {
	sqlQuery :=
		`INSERT INTO closing_documents_requests
			(id, client_id, client_name, status, one_c_guid, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(ctx, sqlQuery,
		req.ID,
		req.ClientID,
		req.ClientName,
		req.Status,
		req.OneCGuid,
		req.CreatedAt,
		req.UpdatedAt,
	)

	if err != nil {
		return err
	}

	return nil
}

func (r *Repository) GetClosingDocumentsRequestByGUID(ctx context.Context, guid uuid.UUID) (entity.ClosingDocumentsRequest, error) {
	sqlQuery := `
SELECT id, client_id, client_name, status, one_c_guid, created_at, updated_at
FROM closing_documents_requests
WHERE one_c_guid = $1`

	var req entity.ClosingDocumentsRequest

	err := r.db.QueryRow(ctx, sqlQuery, guid).
		Scan(
			&req.ID,
			&req.ClientID,
			&req.ClientName,
			&req.Status,
			&req.OneCGuid,
			&req.CreatedAt,
			&req.UpdatedAt,
		)
	if err != nil {
		return entity.ClosingDocumentsRequest{}, err
	}

	return req, nil
}

func (r *Repository) ChangeClosingDocumentsRequestStatus(ctx context.Context, guid uuid.UUID) error {
	sqlQuery := `UPDATE closing_documents_requests SET status = $1 WHERE one_c_guid = $2`

	_, err := r.db.Exec(ctx, sqlQuery, entity.RequestDone, guid)
	if err != nil {
		return err
	}

	return nil
}

func (r *Repository) CreateDocuments(ctx context.Context, documents ...entity.Document) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	for _, doc := range documents {
		sqlQuery :=
			`INSERT INTO documents
			(id, client_id, client_name, name, doc_type, status, created_at, signed_at, sum, url, data, one_c_guid)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

		data, err := json.Marshal(doc.Data)
		if err != nil {
			return err
		}

		_, err = r.db.Exec(ctx, sqlQuery,
			doc.ID,
			doc.ClientID,
			doc.ClientName,
			doc.Name,
			doc.DocType,
			doc.Status,
			doc.CreatedAt,
			doc.SignedAt,
			doc.Sum,
			doc.URL,
			data,
			doc.OneCGuid,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (r *Repository) UpdateDocumentsStatus(
	ctx context.Context,
	oldStatus, newStatus entity.DocStatus,
	signedAt, olderThan time.Time,
) error {
	sqlQuery := `
		UPDATE documents
		SET status = $1, signed_at = $2
		WHERE status = $3 AND created_at <= $4
	`

	_, err := r.db.Exec(ctx, sqlQuery, newStatus, oldStatus, signedAt, olderThan)
	if err != nil {
		return err
	}

	return nil
}

func (r *Repository) DocumentByClientID(ctx context.Context, id uuid.UUID) (entity.Document, error) {
	sqlQuery :=
		`SELECT id, client_id, client_name, name, doc_type, status, created_at, signed_at, sum, url, data, one_c_guid
		FROM documents
		WHERE client_id = $1`

	var document entity.Document

	err := r.db.QueryRow(ctx, sqlQuery, id).Scan(
		&document.ID,
		&document.ClientID,
		&document.ClientName,
		&document.Name,
		&document.DocType,
		&document.Status,
		&document.CreatedAt,
		&document.SignedAt,
		&document.Sum,
		&document.URL,
		&document.Data,
		&document.OneCGuid,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.Document{}, entity.ErrNotFound
		}

		return entity.Document{}, err
	}

	return document, nil
}
