package repository

import "github.com/jackc/pgx/v5/pgxpool"

type Repository struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) (*Repository, error) {
	return &Repository{
		pool: pool,
	}, nil
}

func (r *Repository) SomeFunction() error {
	return nil
}
