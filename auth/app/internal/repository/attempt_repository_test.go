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

const (
	testCaseExistingAttempt = "existing attempt"
)

type AttemptRepositoryTestSuite struct {
	suite.Suite
	repo *repository.AttemptRepository
}

func (ts *AttemptRepositoryTestSuite) SetupTest() {
	ts.repo = repository.NewAttemptRepository(repository.SetupTestDatabase(ts.T()))
}
func TestAttemptRepositoryTestSuite(t *testing.T) { //nolint:paralleltest
	suite.Run(t, new(AttemptRepositoryTestSuite))
}
func (ts *AttemptRepositoryTestSuite) TestSaveAttempt() {
	ctx := context.Background()
	email := fmt.Sprintf("user@example.com", uuid.Must(uuid.NewV4()).String())
	ip := fmt.Sprintf("192.168.1.%d", int(uuid.Must(uuid.NewV4()).Bytes()[0]%255))
	attempt := entity.Attempt{
		ID:        uuid.Must(uuid.NewV4()),
		Type:      entity.AttemptTypeAuth,
		UserID:    &[]uuid.UUID{uuid.Must(uuid.NewV4())}[0],
		Provider:  "email",
		Email:     email,
		IPAddress: ip,
		CodeHash:  "hashed_code_123",
		CreatedAt: time.Now(),
	}
	err := ts.repo.SaveAttempt(ctx, attempt)
	ts.Require().NoError(err)
}
func (ts *AttemptRepositoryTestSuite) TestCountByEmailAndType() {
	ctx := context.Background()
	email := fmt.Sprintf("user@example.com", uuid.Must(uuid.NewV4()).String())
	attemptType := entity.AttemptTypeAuth

	for i := range 3 {
		attempt := entity.Attempt{
			ID:        uuid.Must(uuid.NewV4()),
			Type:      attemptType,
			UserID:    &[]uuid.UUID{uuid.Must(uuid.NewV4())}[0],
			Provider:  "email",
			Email:     email,
			IPAddress: fmt.Sprintf("192.168.1.%d", (time.Now().UnixNano()+int64(i))%255),
			CodeHash:  fmt.Sprintf("hashed_code_%d", i),
			CreatedAt: time.Now(),
		}
		err := ts.repo.SaveAttempt(ctx, attempt)
		ts.Require().NoError(err)
	}

	count, err := ts.repo.CountByEmailAndType(ctx, email, attemptType, time.Now().Add(-1*time.Hour))
	ts.Require().NoError(err)
	ts.Require().Equal(3, count)
}
func (ts *AttemptRepositoryTestSuite) TestCountByIPAndType() {
	ctx := context.Background()
	ipAddress := fmt.Sprintf("192.168.1.%d", int(uuid.Must(uuid.NewV4()).Bytes()[0]%255))
	attemptType := entity.AttemptTypeAuth

	for i := range 2 {
		attempt := entity.Attempt{
			ID:        uuid.Must(uuid.NewV4()),
			Type:      attemptType,
			UserID:    &[]uuid.UUID{uuid.Must(uuid.NewV4())}[0],
			Provider:  "email",
			Email:     fmt.Sprintf("user@example.com", i),
			IPAddress: ipAddress,
			CodeHash:  fmt.Sprintf("hashed_code_%d", i),
			CreatedAt: time.Now(),
		}
		err := ts.repo.SaveAttempt(ctx, attempt)
		ts.Require().NoError(err)
	}

	count, err := ts.repo.CountByIPAndType(ctx, ipAddress, attemptType, time.Now().Add(-1*time.Hour))
	ts.Require().NoError(err)
	ts.Require().Equal(2, count)
}
func (ts *AttemptRepositoryTestSuite) TestGetLastAttemptByEmail() {
	ctx := context.Background()
	email := fmt.Sprintf("user@example.com", time.Now().UnixNano())
	attemptType := entity.AttemptTypeAuth
	attempt := entity.Attempt{
		ID:        uuid.Must(uuid.NewV4()),
		Type:      attemptType,
		UserID:    &[]uuid.UUID{uuid.Must(uuid.NewV4())}[0],
		Provider:  "email",
		Email:     email,
		IPAddress: "0.0.0.0",
		CodeHash:  "hashed_code_123",
		CreatedAt: time.Now(),
	}
	err := ts.repo.SaveAttempt(ctx, attempt)
	ts.Require().NoError(err)
	testCases := []struct {
		name        string
		email       string
		attemptType entity.AttemptType
		errFn       require.ErrorAssertionFunc
		wantAttempt entity.Attempt
	}{
		{
			name:        testCaseExistingAttempt,
			email:       email,
			attemptType: attemptType,
			errFn:       require.NoError,
			wantAttempt: attempt,
		},
		{
			name:        "attempt not found",
			email:       "user@example.com",
			attemptType: attemptType,
			errFn: func(t require.TestingT, err error, _ ...any) {
				require.ErrorIs(t, err, entity.ErrNotFound)
			},
			wantAttempt: entity.Attempt{},
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			gotAttempt, err := ts.repo.GetLastAttemptByEmail(ctx, tc.email, tc.attemptType)
			tc.errFn(ts.T(), err)

			if tc.name == testCaseExistingAttempt {
				ts.Require().Equal(tc.wantAttempt.Email, gotAttempt.Email)
				ts.Require().Equal(tc.wantAttempt.Type, gotAttempt.Type)
			}
		})
	}
}
func (ts *AttemptRepositoryTestSuite) TestGetLastAttemptByIP() {
	ctx := context.Background()
	ipAddress := fmt.Sprintf("192.168.1.%d", int(uuid.Must(uuid.NewV4()).Bytes()[0]%255))
	attemptType := entity.AttemptTypeAuth
	attempt := entity.Attempt{
		ID:        uuid.Must(uuid.NewV4()),
		Type:      attemptType,
		UserID:    &[]uuid.UUID{uuid.Must(uuid.NewV4())}[0],
		Provider:  "email",
		Email:     "user@example.com",
		IPAddress: ipAddress,
		CodeHash:  "hashed_code_123",
		CreatedAt: time.Now(),
	}
	err := ts.repo.SaveAttempt(ctx, attempt)
	ts.Require().NoError(err)
	testCases := []struct {
		name        string
		ipAddress   string
		attemptType entity.AttemptType
		errFn       require.ErrorAssertionFunc
		wantAttempt entity.Attempt
	}{
		{
			name:        testCaseExistingAttempt,
			ipAddress:   ipAddress,
			attemptType: attemptType,
			errFn:       require.NoError,
			wantAttempt: attempt,
		},
		{
			name:        "attempt not found",
			ipAddress:   "192.168.1.999",
			attemptType: attemptType,
			errFn: func(t require.TestingT, err error, _ ...any) {
				require.ErrorIs(t, err, entity.ErrNotFound)
			},
			wantAttempt: entity.Attempt{},
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			gotAttempt, err := ts.repo.GetLastAttemptByIP(ctx, tc.ipAddress, tc.attemptType)
			tc.errFn(ts.T(), err)

			if tc.name == testCaseExistingAttempt {
				ts.Require().Equal(tc.wantAttempt.IPAddress, gotAttempt.IPAddress)
				ts.Require().Equal(tc.wantAttempt.Type, gotAttempt.Type)
			}
		})
	}
}
func (ts *AttemptRepositoryTestSuite) TestAddAttemptBlocks() {
	ctx := context.Background()
	email := fmt.Sprintf("user@example.com", uuid.Must(uuid.NewV4()).String())
	ipAddress := fmt.Sprintf("192.168.1.%d", int(uuid.Must(uuid.NewV4()).Bytes()[0]%255))
	block := entity.AttemptBlock{
		ID:         uuid.Must(uuid.NewV4()),
		Type:       string(entity.AttemptTypeAuth),
		Email:      email,
		IPAddress:  ipAddress,
		StartBlock: time.Now(),
		EndBlock:   time.Now().Add(1 * time.Hour),
	}
	err := ts.repo.AddAttemptBlocks(ctx, block)
	ts.Require().NoError(err)
}
func (ts *AttemptRepositoryTestSuite) TestGetLastBlockByEmail() {
	ctx := context.Background()
	email := fmt.Sprintf("user@example.com", uuid.Must(uuid.NewV4()).String())
	attemptType := entity.AttemptTypeAuth
	ipAddress := fmt.Sprintf("192.168.1.%d", int(uuid.Must(uuid.NewV4()).Bytes()[0]%255))
	block := entity.AttemptBlock{
		ID:         uuid.Must(uuid.NewV4()),
		Type:       string(attemptType),
		Email:      email,
		IPAddress:  ipAddress,
		StartBlock: time.Now(),
		EndBlock:   time.Now().Add(1 * time.Hour),
	}
	err := ts.repo.AddAttemptBlocks(ctx, block)
	ts.Require().NoError(err)
	testCases := []struct {
		name        string
		email       string
		attemptType entity.AttemptType
		errFn       require.ErrorAssertionFunc
		wantBlock   entity.AttemptBlock
	}{
		{
			name:        "existing block",
			email:       email,
			attemptType: attemptType,
			errFn:       require.NoError,
			wantBlock:   block,
		},
		{
			name:        "block not found",
			email:       "user@example.com",
			attemptType: attemptType,
			errFn: func(t require.TestingT, err error, _ ...any) {
				require.ErrorIs(t, err, entity.ErrNotFound)
			},
			wantBlock: entity.AttemptBlock{},
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			gotBlock, err := ts.repo.GetLastBlockByEmail(ctx, tc.email, string(tc.attemptType))
			tc.errFn(ts.T(), err)

			if tc.name == testCaseExistingAttempt {
				ts.Require().Equal(tc.wantBlock.Email, gotBlock.Email)
				ts.Require().Equal(tc.wantBlock.Type, gotBlock.Type)
			}
		})
	}
}
func (ts *AttemptRepositoryTestSuite) TestGetLastBlockByIP() {
	ctx := context.Background()
	ipAddress := fmt.Sprintf("192.168.1.%d", int(uuid.Must(uuid.NewV4()).Bytes()[0]%255))
	attemptType := entity.AttemptTypeAuth
	email := fmt.Sprintf("user@example.com", uuid.Must(uuid.NewV4()).String())
	block := entity.AttemptBlock{
		ID:         uuid.Must(uuid.NewV4()),
		Type:       string(attemptType),
		Email:      email,
		IPAddress:  ipAddress,
		StartBlock: time.Now(),
		EndBlock:   time.Now().Add(1 * time.Hour),
	}
	err := ts.repo.AddAttemptBlocks(ctx, block)
	ts.Require().NoError(err)
	testCases := []struct {
		name        string
		ipAddress   string
		attemptType entity.AttemptType
		errFn       require.ErrorAssertionFunc
		wantBlock   entity.AttemptBlock
	}{
		{
			name:        "existing block",
			ipAddress:   ipAddress,
			attemptType: attemptType,
			errFn:       require.NoError,
			wantBlock:   block,
		},
		{
			name:        "block not found",
			ipAddress:   "192.168.1.999",
			attemptType: attemptType,
			errFn: func(t require.TestingT, err error, _ ...any) {
				require.ErrorIs(t, err, entity.ErrNotFound)
			},
			wantBlock: entity.AttemptBlock{},
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.name, func() {
			gotBlock, err := ts.repo.GetLastBlockByIP(ctx, tc.ipAddress, string(tc.attemptType))
			tc.errFn(ts.T(), err)

			if tc.name == testCaseExistingAttempt {
				ts.Require().Equal(tc.wantBlock.IPAddress, gotBlock.IPAddress)
				ts.Require().Equal(tc.wantBlock.Type, gotBlock.Type)
			}
		})
	}
}
func (ts *AttemptRepositoryTestSuite) TestCleanExpiredBlocks() {
	ctx := context.Background()
	email := fmt.Sprintf("user@example.com", uuid.Must(uuid.NewV4()).String())
	ipAddress := fmt.Sprintf("192.168.1.%d", int(uuid.Must(uuid.NewV4()).Bytes()[0]%255))
	expiredBlock := entity.AttemptBlock{
		ID:         uuid.Must(uuid.NewV4()),
		Type:       string(entity.AttemptTypeAuth),
		Email:      email,
		IPAddress:  ipAddress,
		StartBlock: time.Now().Add(-2 * time.Hour),
		EndBlock:   time.Now().Add(-1 * time.Hour),
	}
	err := ts.repo.AddAttemptBlocks(ctx, expiredBlock)
	ts.Require().NoError(err)
	err = ts.repo.CleanExpiredBlocks(ctx)
	ts.Require().NoError(err)
	_, err = ts.repo.GetLastBlockByEmail(ctx, expiredBlock.Email, expiredBlock.Type)

	if err == nil {
		ts.T().Errorf("Блокировка должна была быть удалена CleanExpiredBlocks, но все еще найдена")
	}
}
