package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/internal/repository"
)

type CodeRepositoryTestSuite struct {
	suite.Suite
	repo *repository.CodeRepository
}

func (ts *CodeRepositoryTestSuite) SetupTest() {
	ts.repo = repository.NewCodeRepository(repository.SetupTestDatabase(ts.T()))
}

func TestCodeRepositoryTestSuite(t *testing.T) { //nolint:paralleltest
	suite.Run(t, new(CodeRepositoryTestSuite))
}

func (ts *CodeRepositoryTestSuite) TestSaveVerificationCode() {
	ctx := context.Background()
	email := "user@example.com"
	action := entity.VerificationActionRegister

	code := entity.VerificationCode{
		ID:             uuid.Must(uuid.NewV4()),
		Email:          email,
		Action:         action,
		CodeHash:       "hashed_code_123",
		ExpirationDate: time.Now().Add(10 * time.Minute),
		CreatedAt:      time.Now(),
	}

	err := ts.repo.SaveVerificationCode(ctx, code)
	ts.Require().NoError(err)
}

func (ts *CodeRepositoryTestSuite) TestFindByEmailAndAction() { //nolint:tparallel
	ctx := context.Background()
	email := "user@example.com"
	action := entity.VerificationActionRegister

	code := entity.VerificationCode{
		ID:             uuid.Must(uuid.NewV4()),
		Email:          email,
		Action:         action,
		CodeHash:       "hashed_code_123",
		ExpirationDate: time.Now().Add(10 * time.Minute),
		CreatedAt:      time.Now(),
	}

	err := ts.repo.SaveVerificationCode(ctx, code)
	ts.Require().NoError(err)

	testCases := []struct {
		name     string
		email    string
		action   entity.VerificationAction
		errFn    require.ErrorAssertionFunc
		wantCode entity.VerificationCode
	}{
		{
			name:     "existing code",
			email:    email,
			action:   action,
			errFn:    require.NoError,
			wantCode: code,
		},
		{
			name:   "code not found",
			email:  "user@example.com",
			action: action,
			errFn: func(t require.TestingT, err error, _ ...any) {
				require.ErrorIs(t, err, entity.ErrNotFound)
			},
			wantCode: entity.VerificationCode{},
		},
	}

	for _, tc := range testCases {
		ts.T().Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotCode, err := ts.repo.FindByEmailAndAction(ctx, tc.email, tc.action)
			tc.errFn(t, err)

			if tc.name == "existing code" {
				require.Equal(t, tc.wantCode.Email, gotCode.Email)
				require.Equal(t, tc.wantCode.Action, gotCode.Action)
				require.Equal(t, tc.wantCode.CodeHash, gotCode.CodeHash)
			}
		})
	}
}

func (ts *CodeRepositoryTestSuite) TestMarkAsUsed() {
	ctx := context.Background()
	email := "user@example.com"
	action := entity.VerificationActionRegister

	code := entity.VerificationCode{
		ID:             uuid.Must(uuid.NewV4()),
		Email:          email,
		Action:         action,
		CodeHash:       "hashed_code_123",
		ExpirationDate: time.Now().Add(10 * time.Minute),
		CreatedAt:      time.Now(),
	}

	err := ts.repo.SaveVerificationCode(ctx, code)
	ts.Require().NoError(err)

	err = ts.repo.MarkAsUsed(ctx, code.ID)
	ts.Require().NoError(err)

	_, err = ts.repo.FindByEmailAndAction(ctx, email, action)
	ts.Require().ErrorIs(err, entity.ErrNotFound)
}

func (ts *CodeRepositoryTestSuite) TestCountByEmailAndAction() {
	ctx := context.Background()
	email := "user@example.com"

	for i := range 3 {
		code := entity.VerificationCode{
			ID:             uuid.Must(uuid.NewV4()),
			Email:          email,
			Action:         entity.VerificationActionRegister,
			CodeHash:       fmt.Sprintf("hashed_code_%d", i),
			ExpirationDate: time.Now().Add(10 * time.Minute),
			CreatedAt:      time.Now(),
		}

		err := ts.repo.SaveVerificationCode(ctx, code)
		ts.Require().NoError(err)
	}

	count, err := ts.repo.CountByEmailAndAction(ctx, email, entity.VerificationActionRegister, time.Now().Add(-1*time.Hour))
	ts.Require().NoError(err)
	ts.Require().Equal(3, count)
}

func (ts *CodeRepositoryTestSuite) TestDeleteByEmail() {
	ctx := context.Background()
	email := "user@example.com"
	action := entity.VerificationActionRegister

	code := entity.VerificationCode{
		ID:             uuid.Must(uuid.NewV4()),
		Email:          email,
		Action:         action,
		CodeHash:       "hashed_code_123",
		ExpirationDate: time.Now().Add(10 * time.Minute),
		CreatedAt:      time.Now(),
	}

	err := ts.repo.SaveVerificationCode(ctx, code)
	ts.Require().NoError(err)

	err = ts.repo.DeleteByEmail(ctx, email)
	ts.Require().NoError(err)

	_, err = ts.repo.FindByEmailAndAction(ctx, email, action)
	ts.Require().ErrorIs(err, entity.ErrNotFound)
}
