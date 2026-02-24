package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/samandr77/microservices/client/internal/entity"
)

func (r *UserRepository) Create(ctx context.Context, user *entity.User) (uuid.UUID, error) {
	userID := uuid.Must(uuid.NewV4())

	query := `
		INSERT INTO users (
			user_id, sub, sub_alt, last_name, first_name, middle_name,
			email, phone, birthdate, city, school_name, place_of_education,
			address_reg, series, number, issued_by, issued_date, code,
			personal_info, role_id, status, verification_status,
			privacy_policy_agreed, newsletter_agreed, public_donations_agreed
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25
		)`

	_, err := r.pool.Exec(ctx, query,
		userID,
		user.Sub,
		user.SubAlt,
		user.LastName,
		user.FirstName,
		user.MiddleName,
		user.Email,
		user.Phone,
		user.Birthdate,
		user.City,
		user.SchoolName,
		user.PlaceOfEducation,
		user.AddressReg,
		user.Series,
		user.Number,
		user.IssuedBy,
		user.IssuedDate,
		user.Code,
		user.PersonalInfo,
		user.RoleID,
		user.Status,
		user.VerificationStatus,
		user.PrivacyPolicyAgreed,
		user.NewsletterAgreed,
		user.PublicDonationsAgreed,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				if strings.Contains(pgErr.ConstraintName, "email") {
					return uuid.Nil, entity.ErrDuplicateEmail
				}

				if strings.Contains(pgErr.ConstraintName, "sub") && !strings.Contains(pgErr.ConstraintName, "sub_alt") {
					return uuid.Nil, entity.ErrDuplicateSub
				}

				if strings.Contains(pgErr.ConstraintName, "sub_alt") {
					return uuid.Nil, entity.ErrDuplicateSubAlt
				}
			}
		}

		return uuid.Nil, err
	}

	return userID, nil
}

func (r *UserRepository) getUser(ctx context.Context, query string, arg interface{}) (*entity.User, error) {
	var user entity.User

	err := r.pool.QueryRow(ctx, query, arg).Scan(
		&user.UserID,
		&user.Sub,
		&user.SubAlt,
		&user.LastName,
		&user.FirstName,
		&user.MiddleName,
		&user.Email,
		&user.Phone,
		&user.Birthdate,
		&user.City,
		&user.SchoolName,
		&user.PlaceOfEducation,
		&user.AddressReg,
		&user.Series,
		&user.Number,
		&user.IssuedBy,
		&user.IssuedDate,
		&user.Code,
		&user.PersonalInfo,
		&user.RoleID,
		&user.Status,
		&user.VerificationStatus,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
		&user.PrivacyPolicyAgreed,
		&user.NewsletterAgreed,
		&user.PublicDonationsAgreed,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, entity.ErrUserNotFound
		}

		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetByID(ctx context.Context, userID uuid.UUID) (*entity.User, error) {
	query := `SELECT * FROM users WHERE user_id = $1`
	return r.getUser(ctx, query, userID)
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	query := `SELECT * FROM users WHERE LOWER(email) = LOWER($1)`
	return r.getUser(ctx, query, email)
}

func (r *UserRepository) GetBySub(ctx context.Context, sub string) (*entity.User, error) {
	query := `SELECT * FROM users WHERE sub = $1`
	return r.getUser(ctx, query, sub)
}

func (r *UserRepository) GetBySubAlt(ctx context.Context, subAlt string) (*entity.User, error) {
	query := `SELECT * FROM users WHERE sub_alt = $1`
	return r.getUser(ctx, query, subAlt)
}

func (r *UserRepository) Update(ctx context.Context, user *entity.User) error {
	query := `
		UPDATE users SET
			sub = $2,
			sub_alt = $3,
			last_name = $4,
			first_name = $5,
			middle_name = $6,
			email = $7,
			phone = $8,
			birthdate = $9,
			city = $10,
			school_name = $11,
			place_of_education = $12,
			address_reg = $13,
			series = $14,
			number = $15,
			issued_by = $16,
			issued_date = $17,
			code = $18,
			personal_info = $19,
			role_id = $20,
			status = $21,
			verification_status = $22,
			privacy_policy_agreed = $23,
			newsletter_agreed = $24,
			public_donations_agreed = $25
		WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query,
		user.UserID,
		user.Sub,
		user.SubAlt,
		user.LastName,
		user.FirstName,
		user.MiddleName,
		user.Email,
		user.Phone,
		user.Birthdate,
		user.City,
		user.SchoolName,
		user.PlaceOfEducation,
		user.AddressReg,
		user.Series,
		user.Number,
		user.IssuedBy,
		user.IssuedDate,
		user.Code,
		user.PersonalInfo,
		user.RoleID,
		user.Status,
		user.VerificationStatus,
		user.PrivacyPolicyAgreed,
		user.NewsletterAgreed,
		user.PublicDonationsAgreed,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				if strings.Contains(pgErr.ConstraintName, "email") {
					return entity.ErrDuplicateEmail
				}

				if strings.Contains(pgErr.ConstraintName, "sub") && !strings.Contains(pgErr.ConstraintName, "sub_alt") {
					return entity.ErrDuplicateSub
				}

				if strings.Contains(pgErr.ConstraintName, "sub_alt") {
					return entity.ErrDuplicateSubAlt
				}
			}
		}

		return err
	}

	return nil
}

func (r *UserRepository) PartialUpdate(ctx context.Context, userID uuid.UUID, fields map[string]any) error {
	if len(fields) == 0 {
		return errors.New("no fields to update")
	}

	setClauses := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+1)

	args = append(args, userID)
	argIndex := 2

	for field, value := range fields {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", field, argIndex))
		args = append(args, value)
		argIndex++
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE user_id = $1", strings.Join(setClauses, ", "))

	_, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				if strings.Contains(pgErr.ConstraintName, "email") {
					return entity.ErrDuplicateEmail
				}

				if strings.Contains(pgErr.ConstraintName, "sub") && !strings.Contains(pgErr.ConstraintName, "sub_alt") {
					return entity.ErrDuplicateSub
				}

				if strings.Contains(pgErr.ConstraintName, "sub_alt") {
					return entity.ErrDuplicateSubAlt
				}
			}
		}

		return err
	}

	return nil
}

func (r *UserRepository) CheckDuplicates(ctx context.Context, email, sub, subAlt *string) (bool, error) {
	const maxConditions = 3
	conditions := make([]string, 0, maxConditions)
	args := make([]any, 0, maxConditions)

	if email != nil {
		conditions = append(conditions, fmt.Sprintf("LOWER(email) = LOWER($%d)", len(args)+1))
		args = append(args, *email)
	}

	if sub != nil {
		conditions = append(conditions, fmt.Sprintf("sub = $%d", len(args)+1))
		args = append(args, *sub)
	}

	if subAlt != nil {
		conditions = append(conditions, fmt.Sprintf("sub_alt = $%d", len(args)+1))
		args = append(args, *subAlt)
	}

	if len(conditions) == 0 {
		return false, nil
	}

	query := fmt.Sprintf(
		"SELECT EXISTS(SELECT 1 FROM users WHERE %s)",
		strings.Join(conditions, " OR "),
	)

	var exists bool
	if err := r.pool.QueryRow(ctx, query, args...).Scan(&exists); err != nil {
		return false, err
	}

	return exists, nil
}

func (r *UserRepository) UpdateStatus(ctx context.Context, userID uuid.UUID, status entity.UserStatus) error {
	query := `UPDATE users SET status = $1, updated_at = NOW() WHERE user_id = $2`

	_, err := r.pool.Exec(ctx, query, status, userID)
	if err != nil {
		return err
	}

	return nil
}

func (r *UserRepository) SetDeletedAt(ctx context.Context, userID uuid.UUID, deletedAt time.Time) error {
	var query string
	if deletedAt.IsZero() {
		query = `UPDATE users SET deleted_at = NULL, updated_at = NOW() WHERE user_id = $1`
		_, err := r.pool.Exec(ctx, query, userID)

		if err != nil {
			return err
		}
	} else {
		query = `UPDATE users SET deleted_at = $1, updated_at = NOW() WHERE user_id = $2`
		_, err := r.pool.Exec(ctx, query, deletedAt, userID)

		if err != nil {
			return err
		}
	}

	return nil
}

func (r *UserRepository) FindByFilters(ctx context.Context, email, sub, subAlt *string) (*entity.User, error) {
	query := `
		SELECT * FROM users
		WHERE (LOWER(email) = LOWER($1) OR sub = CAST($2 AS uuid) OR sub_alt = CAST($3 AS uuid))
		  AND deleted_at IS NULL
		LIMIT 1`

	var user entity.User
	err := r.pool.QueryRow(ctx, query, email, sub, subAlt).Scan(
		&user.UserID,
		&user.Sub,
		&user.SubAlt,
		&user.LastName,
		&user.FirstName,
		&user.MiddleName,
		&user.Email,
		&user.Phone,
		&user.Birthdate,
		&user.City,
		&user.SchoolName,
		&user.PlaceOfEducation,
		&user.AddressReg,
		&user.Series,
		&user.Number,
		&user.IssuedBy,
		&user.IssuedDate,
		&user.Code,
		&user.PersonalInfo,
		&user.RoleID,
		&user.Status,
		&user.VerificationStatus,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
		&user.PrivacyPolicyAgreed,
		&user.NewsletterAgreed,
		&user.PublicDonationsAgreed,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, entity.ErrUserNotFound
		}

		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL)`

	var exists bool
	err := r.pool.QueryRow(ctx, query, email).Scan(&exists)

	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *UserRepository) ExistsBySub(ctx context.Context, sub uuid.UUID) (bool, error) {
	if sub == uuid.Nil {
		return false, nil
	}

	query := `SELECT EXISTS(SELECT 1 FROM users WHERE sub = $1 AND deleted_at IS NULL)`

	var exists bool
	err := r.pool.QueryRow(ctx, query, sub).Scan(&exists)

	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *UserRepository) GetExpiredDeletedAccounts(ctx context.Context, expirationDate time.Time) ([]uuid.UUID, error) {
	query := `
		SELECT user_id FROM users
		WHERE status = 'deleted'
		AND deleted_at IS NOT NULL
		AND deleted_at < $1
		ORDER BY deleted_at ASC`

	rows, err := r.pool.Query(ctx, query, expirationDate)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var userIDs []uuid.UUID

	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}

		userIDs = append(userIDs, userID)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return userIDs, nil
}

func (r *UserRepository) PermanentlyDelete(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM users WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return err
	}

	return nil
}
