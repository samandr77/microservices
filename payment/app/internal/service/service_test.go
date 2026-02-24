package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/samandr77/microservices/payment/internal/entity"
	"github.com/samandr77/microservices/payment/internal/mocks"
	"github.com/samandr77/microservices/payment/internal/service"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestService_UpdateCardPaymentStatus(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	repo := mocks.NewMockRepository(ctrl)
	producer := mocks.NewMockProducer(ctrl)
	bank := mocks.NewMockBankService(ctrl)

	txs := []entity.Transaction{
		{
			ID:        uuid.Must(uuid.NewV4()),
			Status:    entity.TransactionStatusCreated,
			ClientID:  uuid.Must(uuid.NewV4()),
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.Must(uuid.NewV4()),
			ClientID:  uuid.Must(uuid.NewV4()),
			Status:    entity.TransactionStatusCreated,
			CreatedAt: time.Now(),
		},
	}

	repo.EXPECT().NotPaidTransactions(context.Background(), entity.PaymentMethodCard).Return(txs, nil)
	bank.EXPECT().CardPaymentStatus(context.Background(), gomock.Any()).
		Return(entity.CardPaymentStatusAuthorizedCompleted, nil).Times(len(txs))
	repo.EXPECT().UpdateTransactionStatus(context.Background(), gomock.Any(), entity.TransactionStatusPaid, gomock.Any()).
		Return(nil).Times(len(txs))
	producer.EXPECT().SendUpdateBalance(context.Background(), gomock.Any(), gomock.Any(), gomock.Any()).Times(len(txs))

	s := service.New(repo, nil, nil, producer, bank)

	err := s.UpdateCardPaymentStatus(context.Background())
	require.NoError(t, err)
}
