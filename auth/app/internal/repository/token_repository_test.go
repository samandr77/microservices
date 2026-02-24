package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/suite"
	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/internal/repository"
)

type TokenRepositoryTestSuite struct {
	suite.Suite
	repo *repository.RefreshTokenRepository
}

func (ts *TokenRepositoryTestSuite) SetupTest() {
	ts.repo = repository.NewRefreshTokenRepository(repository.SetupTestDatabase(ts.T()))
}

func TestTokenRepositoryTestSuite(t *testing.T) { //nolint:paralleltest
	suite.Run(t, new(TokenRepositoryTestSuite))
}

func (ts *TokenRepositoryTestSuite) TestSaveRefreshToken() {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	token := "test_refresh_token_123"
	expiresAt := time.Now().Add(24 * time.Hour)

	err := ts.repo.SaveRefreshToken(ctx, userID, token, expiresAt)
	ts.Require().NoError(err)
}

func (ts *TokenRepositoryTestSuite) TestFindRefreshToken() {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	token := "test_token_" + uuid.Must(uuid.NewV4()).String()
	expiresAt := time.Now().Add(24 * time.Hour)

	err := ts.repo.SaveRefreshToken(ctx, userID, token, expiresAt)
	ts.Require().NoError(err)

	ts.Run("existing_token", func() {
		err := ts.repo.FindRefreshToken(ctx, token)
		ts.Require().NoError(err)
	})

	ts.Run("non_existing_token", func() {
		err := ts.repo.FindRefreshToken(ctx, "non_existing_token")
		ts.Require().Error(err)
		ts.Require().Equal(entity.ErrNotFound, err)
	})

	ts.Run("expired_token", func() {
		expiredToken := "expired_token_" + uuid.Must(uuid.NewV4()).String()
		pastTime := time.Now().Add(-24 * time.Hour)

		err := ts.repo.SaveRefreshToken(ctx, userID, expiredToken, pastTime)
		ts.Require().NoError(err)

		err = ts.repo.FindRefreshToken(ctx, expiredToken)
		ts.Require().Error(err)
		ts.Require().Equal(entity.ErrNotFound, err)
	})
}

func (ts *TokenRepositoryTestSuite) TestDeleteRefreshToken() {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	token := "test_token_" + uuid.Must(uuid.NewV4()).String()
	expiresAt := time.Now().Add(24 * time.Hour)

	err := ts.repo.SaveRefreshToken(ctx, userID, token, expiresAt)
	ts.Require().NoError(err)

	err = ts.repo.FindRefreshToken(ctx, token)
	ts.Require().NoError(err)

	err = ts.repo.DeleteRefreshToken(ctx, token)
	ts.Require().NoError(err)

	err = ts.repo.FindRefreshToken(ctx, token)
	ts.Require().Error(err)
	ts.Require().Equal(entity.ErrNotFound, err)
}

func (ts *TokenRepositoryTestSuite) TestDeleteByUserID() {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	token1 := "test_token_1_" + uuid.Must(uuid.NewV4()).String()
	token2 := "test_token_2_" + uuid.Must(uuid.NewV4()).String()
	expiresAt := time.Now().Add(24 * time.Hour)

	err := ts.repo.SaveRefreshToken(ctx, userID, token1, expiresAt)
	ts.Require().NoError(err)

	err = ts.repo.SaveRefreshToken(ctx, userID, token2, expiresAt)
	ts.Require().NoError(err)

	err = ts.repo.FindRefreshToken(ctx, token1)
	ts.Require().NoError(err)

	err = ts.repo.FindRefreshToken(ctx, token2)
	ts.Require().NoError(err)

	err = ts.repo.DeleteByUserID(ctx, userID)
	ts.Require().NoError(err)

	err = ts.repo.FindRefreshToken(ctx, token1)
	ts.Require().Error(err)
	ts.Require().Equal(entity.ErrNotFound, err)

	err = ts.repo.FindRefreshToken(ctx, token2)
	ts.Require().Error(err)
	ts.Require().Equal(entity.ErrNotFound, err)
}

func (ts *TokenRepositoryTestSuite) TestCleanExpired() {
	ctx := context.Background()
	userID := uuid.Must(uuid.NewV4())
	validToken := "valid_token_" + uuid.Must(uuid.NewV4()).String()
	expiredToken := "expired_token_" + uuid.Must(uuid.NewV4()).String()

	validExpiresAt := time.Now().Add(24 * time.Hour)
	expiredExpiresAt := time.Now().Add(-24 * time.Hour)

	err := ts.repo.SaveRefreshToken(ctx, userID, validToken, validExpiresAt)
	ts.Require().NoError(err)

	err = ts.repo.SaveRefreshToken(ctx, userID, expiredToken, expiredExpiresAt)
	ts.Require().NoError(err)

	err = ts.repo.CleanExpired(ctx)
	ts.Require().NoError(err)

	err = ts.repo.FindRefreshToken(ctx, validToken)
	ts.Require().NoError(err)

	err = ts.repo.FindRefreshToken(ctx, expiredToken)
	ts.Require().Error(err)
	ts.Require().Equal(entity.ErrNotFound, err)
}
