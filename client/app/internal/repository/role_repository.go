package repository

import (
	"context"
	"errors"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"

	"github.com/samandr77/microservices/client/internal/entity"
)

func (r *RoleRepository) GetByID(ctx context.Context, roleID uuid.UUID) (*entity.Role, error) {
	query := `SELECT id, role_name FROM roles WHERE id = $1`

	var role entity.Role
	err := r.pool.QueryRow(ctx, query, roleID).Scan(&role.ID, &role.Name)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("role not found")
		}

		return nil, err
	}

	return &role, nil
}

func (r *RoleRepository) GetByName(ctx context.Context, roleName string) (*entity.Role, error) {
	query := `SELECT id, role_name FROM roles WHERE role_name = $1`

	var role entity.Role
	err := r.pool.QueryRow(ctx, query, roleName).Scan(&role.ID, &role.Name)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("role not found")
		}

		return nil, err
	}

	return &role, nil
}

func (r *RoleRepository) GetAll(ctx context.Context) ([]*entity.Role, error) {
	query := `SELECT id, role_name FROM roles ORDER BY role_name`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*entity.Role

	for rows.Next() {
		var role entity.Role
		if err := rows.Scan(&role.ID, &role.Name); err != nil {
			return nil, err
		}

		roles = append(roles, &role)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

func (r *RoleRepository) Create(ctx context.Context, role *entity.Role) error {
	query := `INSERT INTO roles (id, role_name) VALUES ($1, $2)`

	_, err := r.pool.Exec(ctx, query, role.ID, role.Name)
	if err != nil {
		return err
	}

	return nil
}

func (r *RoleRepository) GetRoleByUserID(ctx context.Context, userID uuid.UUID) (*entity.Role, error) {
	query := `SELECT r.id, r.role_name FROM roles r
	          JOIN users u ON r.id = u.role_id
	          WHERE u.user_id = $1`

	var role entity.Role
	err := r.pool.QueryRow(ctx, query, userID).Scan(&role.ID, &role.Name)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("role not found")
		}

		return nil, err
	}

	return &role, nil
}
