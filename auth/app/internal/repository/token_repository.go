package repository

import (
	"context"
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/samandr77/microservices/auth/internal/entity"
)

type RefreshTokenRepository struct {
	db *pgxpool.Pool
}

func NewRefreshTokenRepository(db *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) SaveRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	q := `INSERT INTO token (user_id, refresh_token, refresh_token_expire) VALUES ($1, $2, $3)`

	_, err := r.db.Exec(ctx, q, userID, token, expiresAt.Unix())
	if err != nil {
		return err
	}

	return nil
}

func (r *RefreshTokenRepository) FindRefreshToken(ctx context.Context, token string) error {
	var foundToken string

	q := `
	SELECT refresh_token
	FROM token
	WHERE refresh_token = $1
	AND refresh_token_expire > EXTRACT(EPOCH FROM NOW())`

	err := r.db.QueryRow(ctx, q, token).Scan(&foundToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return entity.ErrNotFound
		}

		return err
	}

	return nil
}

func (r *RefreshTokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	q := `DELETE FROM token WHERE refresh_token = $1`

	_, err := r.db.Exec(ctx, q, token)
	if err != nil {
		return err
	}

	return nil
}

func (r *RefreshTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	q := `DELETE FROM token WHERE user_id = $1`

	_, err := r.db.Exec(ctx, q, userID)
	if err != nil {
		return err
	}

	return nil
}

func (r *RefreshTokenRepository) CleanExpired(ctx context.Context) error {
	q := `DELETE FROM token WHERE refresh_token_expire < EXTRACT(EPOCH FROM NOW())`

	_, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}

	return nil
}

func (r *RefreshTokenRepository) HasActiveTokenForUser(ctx context.Context, userID uuid.UUID) error {
	var exists bool

	q := `
	SELECT EXISTS(
		SELECT 1
		FROM token
		WHERE user_id = $1
		AND refresh_token_expire > EXTRACT(EPOCH FROM NOW())
	)`

	err := r.db.QueryRow(ctx, q, userID).Scan(&exists)
	if err != nil {
		return err
	}

	if !exists {
		return entity.ErrNotFound
	}

	return nil
}

func (r *RefreshTokenRepository) GetActiveRefreshTokensByUserID(ctx context.Context, userID uuid.UUID) ([]string, error) {
	var tokens []string

	q := `
	SELECT refresh_token
	FROM token
	WHERE user_id = $1
	AND refresh_token_expire > EXTRACT(EPOCH FROM NOW())`

	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, err
		}

		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tokens, nil
}
