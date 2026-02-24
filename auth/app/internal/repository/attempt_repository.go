package repository

import (
	"context"
	"errors"
	"time"

	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/samandr77/microservices/auth/internal/entity"
)

type AttemptRepository struct {
	db *pgxpool.Pool
}

func NewAttemptRepository(db *pgxpool.Pool) *AttemptRepository {
	return &AttemptRepository{db: db}
}

func (r *AttemptRepository) SaveAttempt(ctx context.Context, attempt entity.Attempt) error {
	q := `
	INSERT INTO attempts (id, type, user_id, provider, email, ip_address, code_hash, created_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.Exec(
		ctx,
		q,
		attempt.ID,
		attempt.Type,
		attempt.UserID,
		attempt.Provider,
		attempt.Email,
		attempt.IPAddress,
		attempt.CodeHash,
		attempt.CreatedAt)
	if err != nil {
		return err
	}

	return nil
}

func (r *AttemptRepository) CountByEmailAndType(
	ctx context.Context,
	email string,
	attemptType entity.AttemptType,
	since time.Time,
) (int, error) {
	var count int

	q := `
		SELECT COUNT(*)
		FROM attempts
		WHERE email = $1 AND type = $2 AND created_at > $3
	`

	err := r.db.QueryRow(ctx, q, email, attemptType, since).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (r *AttemptRepository) CountByIPAndType(
	ctx context.Context,
	ipAddress string,
	attemptType entity.AttemptType,
	since time.Time,
) (int, error) {
	var count int

	q := `
		SELECT COUNT(*)
		FROM attempts
		WHERE ip_address = $1 AND type = $2 AND created_at > $3
	`

	err := r.db.QueryRow(ctx, q, ipAddress, attemptType, since).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (r *AttemptRepository) GetLastAttemptByEmail(
	ctx context.Context,
	email string,
	attemptType entity.AttemptType,
) (entity.Attempt, error) {
	var attempt entity.Attempt

	q := `
		SELECT id, type, user_id, provider, email, ip_address, code_hash, created_at
		FROM attempts
		WHERE email = $1 AND type = $2
		ORDER BY created_at DESC
		LIMIT 1
	`

	err := r.db.QueryRow(ctx, q, email, attemptType).Scan(
		&attempt.ID,
		&attempt.Type,
		&attempt.UserID,
		&attempt.Provider,
		&attempt.Email,
		&attempt.IPAddress,
		&attempt.CodeHash,
		&attempt.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return attempt, entity.ErrNotFound
		}

		return attempt, err
	}

	return attempt, nil
}

func (r *AttemptRepository) GetLastAttemptByIP(
	ctx context.Context,
	ipAddress string,
	attemptType entity.AttemptType,
) (entity.Attempt, error) {
	var attempt entity.Attempt

	q := `
		SELECT id, type, user_id, provider, email, ip_address, code_hash, created_at
		FROM attempts
		WHERE ip_address = $1 AND type = $2
		ORDER BY created_at DESC
		LIMIT 1
	`

	err := r.db.QueryRow(ctx, q, ipAddress, attemptType).Scan(
		&attempt.ID,
		&attempt.Type,
		&attempt.UserID,
		&attempt.Provider,
		&attempt.Email,
		&attempt.IPAddress,
		&attempt.CodeHash,
		&attempt.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return attempt, entity.ErrNotFound
		}

		return attempt, err
	}

	return attempt, nil
}

func (r *AttemptRepository) GetLastBlockByEmail(ctx context.Context, email string, attemptType string) (entity.AttemptBlock, error) {
	var block entity.AttemptBlock

	q := `
		SELECT id, email, ip_address, start_block, end_block, type
		FROM attempts_blocks
		WHERE email = $1 AND type = $2 AND end_block > NOW()
		ORDER BY start_block DESC
		LIMIT 1
	`

	err := r.db.QueryRow(ctx, q, email, attemptType).Scan(
		&block.ID,
		&block.Email,
		&block.IPAddress,
		&block.StartBlock,
		&block.EndBlock,
		&block.Type,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return block, entity.ErrNotFound
		}

		return block, err
	}

	return block, nil
}

func (r *AttemptRepository) GetLastBlockByIP(ctx context.Context, ipAddress string, attemptType string) (entity.AttemptBlock, error) {
	var block entity.AttemptBlock

	q := `
		SELECT id, email, ip_address, start_block, end_block, type
		FROM attempts_blocks
		WHERE ip_address = $1 AND type = $2 AND end_block > NOW()
		ORDER BY start_block DESC
		LIMIT 1
	`

	err := r.db.QueryRow(ctx, q, ipAddress, attemptType).Scan(
		&block.ID,
		&block.Email,
		&block.IPAddress,
		&block.StartBlock,
		&block.EndBlock,
		&block.Type,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return block, entity.ErrNotFound
		}

		return block, err
	}

	return block, nil
}

func (r *AttemptRepository) CleanExpiredBlocks(ctx context.Context) error {
	q := `DELETE FROM attempts_blocks WHERE end_block < NOW()`

	_, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}

	return nil
}

func (r *AttemptRepository) LastAttemptBlockByIP(
	ctx context.Context,
	ipAddress string,
	attemptType entity.AttemptType,
) (entity.AttemptBlock, error) {
	var block entity.AttemptBlock

	q := `
		SELECT id, email, ip_address, start_block, end_block, type
		FROM attempts_blocks
		WHERE ip_address = $1 AND type = $2
		ORDER BY start_block DESC
		LIMIT 1
	`

	err := r.db.QueryRow(ctx, q, ipAddress, attemptType).Scan(
		&block.ID,
		&block.Email,
		&block.IPAddress,
		&block.StartBlock,
		&block.EndBlock,
		&block.Type,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return block, entity.ErrNotFound
		}

		return block, err
	}

	return block, nil
}

func (r *AttemptRepository) AttemptsByIP(ctx context.Context,
	ipAddress string,
	attemptType entity.AttemptType,
	createdAt time.Time,
) ([]entity.Attempt, error) {
	q := `
		SELECT id, type, user_id, provider, email, ip_address, code_hash, created_at
		FROM attempts
		WHERE ip_address = $1 AND type = $2 AND created_at > $3
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, q, ipAddress, attemptType, createdAt)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var attempts []entity.Attempt

	for rows.Next() {
		var attempt entity.Attempt
		err := rows.Scan(
			&attempt.ID,
			&attempt.Type,
			&attempt.UserID,
			&attempt.Provider,
			&attempt.Email,
			&attempt.IPAddress,
			&attempt.CodeHash,
			&attempt.CreatedAt,
		)

		if err != nil {
			return nil, err
		}

		attempts = append(attempts, attempt)
	}

	return attempts, nil
}

func (r *AttemptRepository) AttemptsByEmailAndIP(
	ctx context.Context,
	email string,
	ipAddress string,
	attemptType entity.AttemptType,
	since time.Time,
) ([]entity.Attempt, error) {
	q := `
		SELECT id, type, user_id, provider, email, ip_address, code_hash, created_at
		FROM attempts
		WHERE email = $1 AND ip_address = $2 AND type = $3 AND created_at > $4
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, q, email, ipAddress, attemptType, since)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var attempts []entity.Attempt

	for rows.Next() {
		var attempt entity.Attempt
		err := rows.Scan(
			&attempt.ID,
			&attempt.Type,
			&attempt.UserID,
			&attempt.Provider,
			&attempt.Email,
			&attempt.IPAddress,
			&attempt.CodeHash,
			&attempt.CreatedAt,
		)

		if err != nil {
			return nil, err
		}

		attempts = append(attempts, attempt)
	}

	return attempts, nil
}

func (r *AttemptRepository) SendAttemptsByEmailAndIP(
	ctx context.Context,
	email string,
	ipAddress string,
	attemptType entity.AttemptType,
	since time.Time,
) ([]entity.Attempt, error) {
	q := `
		SELECT id, type, user_id, provider, email, ip_address, code_hash, created_at
		FROM attempts
		WHERE email = $1 AND ip_address = $2 AND type = $3 AND created_at > $4 AND code_hash = ''
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, q, email, ipAddress, attemptType, since)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var attempts []entity.Attempt

	for rows.Next() {
		var attempt entity.Attempt
		err := rows.Scan(
			&attempt.ID,
			&attempt.Type,
			&attempt.UserID,
			&attempt.Provider,
			&attempt.Email,
			&attempt.IPAddress,
			&attempt.CodeHash,
			&attempt.CreatedAt,
		)

		if err != nil {
			return nil, err
		}

		attempts = append(attempts, attempt)
	}

	return attempts, nil
}

func (r *AttemptRepository) CheckAttemptsByEmailAndIP(
	ctx context.Context,
	email string,
	ipAddress string,
	attemptType entity.AttemptType,
	since time.Time,
) ([]entity.Attempt, error) {
	q := `
		SELECT id, type, user_id, provider, email, ip_address, code_hash, created_at
		FROM attempts
		WHERE email = $1 AND ip_address = $2 AND type = $3 AND created_at > $4 AND code_hash != ''
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, q, email, ipAddress, attemptType, since)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var attempts []entity.Attempt

	for rows.Next() {
		var attempt entity.Attempt
		err := rows.Scan(
			&attempt.ID,
			&attempt.Type,
			&attempt.UserID,
			&attempt.Provider,
			&attempt.Email,
			&attempt.IPAddress,
			&attempt.CodeHash,
			&attempt.CreatedAt,
		)

		if err != nil {
			return nil, err
		}

		attempts = append(attempts, attempt)
	}

	return attempts, nil
}

func (r *AttemptRepository) AddAttemptBlocks(ctx context.Context, attemptBlocks entity.AttemptBlock) error {
	q := `
		INSERT INTO attempts_blocks (id, email, ip_address, start_block, end_block, type)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.Exec(
		ctx,
		q,
		attemptBlocks.ID,
		attemptBlocks.Email,
		attemptBlocks.IPAddress,
		attemptBlocks.StartBlock,
		attemptBlocks.EndBlock,
		attemptBlocks.Type,
	)
	if err != nil {
		return err
	}

	return nil
}
