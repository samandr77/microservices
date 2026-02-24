package repository

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

type RoleRepository struct {
	pool *pgxpool.Pool
}

type UserBlockRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func NewRoleRepository(pool *pgxpool.Pool) *RoleRepository {
	return &RoleRepository{pool: pool}
}

func NewUserBlockRepository(pool *pgxpool.Pool) *UserBlockRepository {
	return &UserBlockRepository{pool: pool}
}
