package repository

import (
	"context"
	"errors"
	"time"

	uuid "github.com/gofrs/uuid/v5"
	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/samandr77/microservices/auth/internal/entity"
)

type CodeRepository struct {
	db *pgxpool.Pool
}

func NewCodeRepository(db *pgxpool.Pool) *CodeRepository {
	return &CodeRepository{db: db}
}

func (r *CodeRepository) SaveVerificationCode(ctx context.Context, code entity.VerificationCode) error {
	q := `
	INSERT INTO verification_codes (
		id, email, action, code_hash, expiration_date, created_at, is_used,
		first_name, last_name, privacy_policy_agreed, newsletter_agreed, public_donations_agreed
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.db.Exec(
		ctx, q,
		code.ID, code.Email, code.Action, code.CodeHash,
		code.ExpirationDate, code.CreatedAt, code.IsUsed,
		code.FirstName, code.LastName,
		code.PrivacyPolicyAgreed, code.NewsletterAgreed, code.PublicDonationsAgreed,
	)
	if err != nil {
		return err
	}

	return nil
}

func (r *CodeRepository) FindByEmailAndAction(
	ctx context.Context,
	email string,
	action entity.VerificationAction,
) (entity.VerificationCode, error) {
	var code entity.VerificationCode

	q := `
	SELECT 
		id, email, action, code_hash, is_used, expiration_date, created_at,
		first_name, last_name, privacy_policy_agreed, newsletter_agreed, public_donations_agreed
	FROM verification_codes
	WHERE email = $1 AND action = $2 AND is_used = FALSE AND expiration_date > NOW()
	ORDER BY created_at DESC
	LIMIT 1
	`

	err := r.db.QueryRow(ctx, q, email, action).Scan(
		&code.ID, &code.Email, &code.Action, &code.CodeHash, &code.IsUsed, &code.ExpirationDate, &code.CreatedAt, &code.FirstName, &code.LastName,
		&code.PrivacyPolicyAgreed, &code.NewsletterAgreed, &code.PublicDonationsAgreed,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return code, entity.ErrNotFound
		}

		return code, err
	}

	return code, nil
}

func (r *CodeRepository) MarkAsUsed(ctx context.Context, codeID uuid.UUID) error {
	q := `UPDATE verification_codes SET is_used = TRUE WHERE id = $1`

	result, err := r.db.Exec(ctx, q, codeID)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return entity.ErrNotFound
	}

	return nil
}

func (r *CodeRepository) DeleteExpiredCode(ctx context.Context) error {
	q := `DELETE FROM verification_codes WHERE NOW() > expiration_date AND is_used = FALSE`

	_, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}

	return nil
}

func (r *CodeRepository) DeleteUsedCodes(ctx context.Context) error {
	q := `DELETE FROM verification_codes
		  WHERE is_used = TRUE
		  AND expiration_date < NOW() - INTERVAL '1 day'`

	_, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}

	return nil
}

func (r *CodeRepository) CountByEmailAndAction(
	ctx context.Context,
	email string,
	action entity.VerificationAction,
	since time.Time,
) (int, error) {
	var count int

	q := `
	SELECT COUNT(*)
	FROM verification_codes
	WHERE email = $1 AND action = $2 AND created_at > $3 AND is_used = FALSE
	`

	err := r.db.QueryRow(ctx, q, email, action, since).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (r *CodeRepository) LastVerificationCode(ctx context.Context, email string) (entity.VerificationCode, error) {
	var code entity.VerificationCode

	q := `
	SELECT id, email, action, code_hash, is_used, expiration_date, created_at
	FROM verification_codes
	WHERE email = $1
	ORDER BY created_at DESC
	LIMIT 1
	`

	err := r.db.QueryRow(ctx, q, email).Scan(
		&code.ID, &code.Email, &code.Action, &code.CodeHash, &code.IsUsed, &code.ExpirationDate, &code.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return code, entity.ErrNotFound
		}

		return code, err
	}

	return code, nil
}

func (r *CodeRepository) DeleteCode(ctx context.Context, codeID uuid.UUID) error {
	q := `DELETE FROM verification_codes WHERE id = $1`

	result, err := r.db.Exec(ctx, q, codeID)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return entity.ErrNotFound
	}

	return nil
}

func (r *CodeRepository) DeleteByEmail(ctx context.Context, email string) error {
	q := `DELETE FROM verification_codes WHERE email = $1`

	_, err := r.db.Exec(ctx, q, email)
	if err != nil {
		return err
	}

	return nil
}
