package repository

import (
	"context"
	"errors"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"

	"github.com/samandr77/microservices/client/internal/entity"
)

func (r *UserBlockRepository) GetByUserID(ctx context.Context, userID uuid.UUID) (*entity.UserBlock, error) {
	query := `SELECT * FROM user_blocks WHERE user_id = $1`

	var block entity.UserBlock
	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&block.ID,
		&block.UserID,
		&block.BlockedTo,
		&block.BlockType,
		&block.BlocksByPeriod,
		&block.FirstBlockDateByPeriod,
		&block.CreatedAt,
		&block.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, entity.ErrBlockNotFound
		}

		return nil, err
	}

	return &block, nil
}

func (r *UserBlockRepository) Create(ctx context.Context, block *entity.UserBlock) error {
	query := `INSERT INTO user_blocks (id, user_id, blocked_to, block_type, blocks_by_period, first_block_date_by_period)
			  VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := r.pool.Exec(ctx, query,
		block.ID,
		block.UserID,
		block.BlockedTo,
		block.BlockType,
		block.BlocksByPeriod,
		block.FirstBlockDateByPeriod,
	)

	if err != nil {
		return err
	}

	return nil
}

func (r *UserBlockRepository) Update(ctx context.Context, block *entity.UserBlock) error {
	query := `UPDATE user_blocks
			  SET blocked_to = $1,
				  block_type = $2,
				  blocks_by_period = $3,
				  first_block_date_by_period = $4,
				  updated_at = NOW()
			  WHERE user_id = $5`

	_, err := r.pool.Exec(ctx, query,
		block.BlockedTo,
		block.BlockType,
		block.BlocksByPeriod,
		block.FirstBlockDateByPeriod,
		block.UserID,
	)

	if err != nil {
		return err
	}

	return nil
}

func (r *UserBlockRepository) Delete(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM user_blocks WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return err
	}

	return nil
}

func (r *UserBlockRepository) GetExpiredTemporaryBlocks(ctx context.Context) ([]*entity.UserBlock, error) {
	query := `SELECT * FROM user_blocks
			  WHERE block_type = '1'
				AND blocked_to IS NOT NULL
				AND blocked_to < NOW()`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []*entity.UserBlock

	for rows.Next() {
		var block entity.UserBlock
		err := rows.Scan(
			&block.ID,
			&block.UserID,
			&block.BlockedTo,
			&block.BlockType,
			&block.BlocksByPeriod,
			&block.FirstBlockDateByPeriod,
			&block.CreatedAt,
			&block.UpdatedAt,
		)

		if err != nil {
			return nil, err
		}

		blocks = append(blocks, &block)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return blocks, nil
}

func (r *UserBlockRepository) IncrementBlockCounter(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE user_blocks
			  SET blocks_by_period = blocks_by_period + 1,
				  updated_at = NOW()
			  WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return err
	}

	return nil
}

func (r *UserBlockRepository) ResetBlockCounter(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE user_blocks
			  SET blocks_by_period = 0,
				  first_block_date_by_period = NULL,
				  updated_at = NOW()
			  WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return err
	}

	return nil
}
