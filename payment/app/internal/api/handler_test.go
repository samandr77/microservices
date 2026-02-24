package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/samandr77/microservices/payment/internal/api"
	"github.com/samandr77/microservices/payment/internal/api/gen/health"
	"github.com/samandr77/microservices/payment/internal/api/gen/models"
	"github.com/samandr77/microservices/payment/internal/api/gen/payments"
	"github.com/samandr77/microservices/payment/internal/entity"
	"github.com/samandr77/microservices/payment/internal/mocks"
	"github.com/samandr77/microservices/payment/internal/repository"
	"github.com/samandr77/microservices/payment/internal/service"
	"github.com/samandr77/microservices/payment/pkg/postgres"
)

func TestHandler_CreateInvoice(t *testing.T) {
	t.Parallel()

	c := NewClientAPI(t)

	user := entity.User{
		ID:        uuid.Must(uuid.NewV4()),
		FirstName: "Test first name",
		LastName:  "Test last name",
		Email:     "user@example.com",
		Role: entity.UserRole{
			Name: entity.RoleManager,
		},
	}

	c.authMock.EXPECT().User(gomock.Any(), "dev").Return(user, nil)

	client := entity.Client{
		ID:        uuid.Must(uuid.NewV4()),
		GUID:      uuid.Must(uuid.NewV4()),
		Name:      "Test name",
		ShortName: "Test short name",
		INN:       "1234567890",
		KPP:       "459697080",
		OGRN:      "0987654321",
		Status:    entity.ClientStatusApproved,
		Oferta: entity.ClientOferta{
			Status: entity.OfertaStatusSigned,
		},
		Employee: entity.Employee{
			Status: entity.EmployeeStatusActive,
			Role:   entity.EmployeeRoleAdmin,
		},
		Address: entity.Address{
			Country: "some country",
			Region:  "some region",
			City:    "some city",
			Index:   "123456",
			Street:  "some street",
		},
	}

	c.clientMock.EXPECT().UserClient(gomock.Any(), user.ID).Return(client, nil)

	requisites := entity.ClientRequisites{
		Name:                     "Test requisites company name",
		INN:                      "1234567890",
		KPP:                      "0987654321",
		Address:                  "Test requisites company address",
		BankBic:                  "0987654321",
		BankCorrespondentAccount: "0987654321",
		BankAccountNumber:        "0987654321",
		BankName:                 "Test requisites bank name",
	}

	c._1CMock.EXPECT().CreateBill(gomock.Any(), gomock.Any()).Return(requisites, nil)

	req := payments.NewPostPaymentsInvoicesParams().WithCreateInvoiceRequest(
		&models.APICreateInvoiceRequest{
			Amount: 1500.25,
		},
	)

	resp, err := c.api.PostPaymentsInvoices(req, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.Code())

	want := &models.APICreateInvoiceResponse{
		Amount:            "1500.25",
		ClientAddress:     "some country, some region, some city, 123456, some street",
		ClientINN:         "1234567890",
		ClientMailAddress: "some country, some region, some city, 123456, some street",
		ClientMailIndex:   "123456",
		ClientName:        "Test name",
		ClientOGRN:        "0987654321",
		ClientKPP:         "459697080",
		TxID:              resp.Payload.TxID,
		PayerType:         entity.PayerTypeCompany,
		Service:           entity.ServiceDefault,
		Requisites: &models.EntityClientRequisites{
			Address:                  requisites.Address,
			BankAccountNumber:        requisites.BankAccountNumber,
			BankBic:                  requisites.BankBic,
			BankCorrespondentAccount: requisites.BankCorrespondentAccount,
			BankName:                 requisites.BankName,
			Inn:                      requisites.INN,
			Kpp:                      requisites.KPP,
			Name:                     requisites.Name,
		},
		Number: resp.Payload.Number,
	}

	require.NotZero(t, resp.Payload.TxID)
	require.NotZero(t, resp.Payload.Number)
	require.Equal(t, want, resp.Payload)
}

func TestHandler_CreateInvoice_Error(t *testing.T) {
	t.Parallel()

	c := NewClientAPI(t)

	c.authMock.EXPECT().User(gomock.Any(), "dev").Return(entity.User{}, entity.ErrUnauthenticated)

	req := payments.NewPostPaymentsInvoicesParams().WithCreateInvoiceRequest(
		&models.APICreateInvoiceRequest{
			Amount: 1500.25,
		},
	)

	_, err := c.api.PostPaymentsInvoices(req, nil)
	require.Error(t, err)
}

func TestHandler_InvoiceCallback(t *testing.T) {
	t.Parallel()

	c := NewClientAPI(t)

	// Create test transaction to check invoice callback.
	now := time.Now()

	tx := entity.Transaction{
		ID:             uuid.Must(uuid.NewV4()),
		ClientID:       uuid.Must(uuid.NewV4()),
		Number:         0, // Fill in by CreateTransaction method.
		ClientGUID:     uuid.Must(uuid.NewV4()),
		Amount:         decimal.RequireFromString("1500.25"),
		TaxRatePercent: entity.DefaultTaxRatePercent,
		PaymentMethod:  entity.PaymentMethodInvoice,
		Status:         entity.TransactionStatusCreated,
		CreatedBy:      uuid.Must(uuid.NewV4()),
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err := c.repo.CreateTransaction(context.Background(), tx)
	require.NoError(t, err)

	// Set producer expected call
	c.producerMock.EXPECT().SendUpdateBalance(gomock.Any(), tx.ID, tx.ClientID, tx.Amount)

	// Check invoice callback.
	req := payments.NewPostPrivateV1OnecInvoiceParams().WithInvoiceCallbackRequest(
		&models.APIInvoiceCallbackRequest{
			BillDate:    time.Now().Format(time.RFC3339),
			BillNumber:  float64(tx.Number),
			GUID:        tx.ClientGUID.String(),
			TotalAmount: tx.Amount.InexactFloat64(),
		})

	resp, err := c.api.PostPrivateV1OnecInvoice(req, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.Code())

	// Check transaction status.
	tx, err = c.repo.TransactionByGUID(context.Background(), tx.ClientGUID, tx.Number)
	require.NoError(t, err)
	require.Equal(t, entity.TransactionStatusPaid, tx.Status)
}

func TestHandler_CreateSPBLink(t *testing.T) {
	t.Parallel()

	c := NewClientAPI(t)

	user := entity.User{
		ID:        uuid.Must(uuid.NewV4()),
		FirstName: "Test first name",
		LastName:  "Test last name",
		Email:     uuid.Must(uuid.NewV4()).String() + "@example.com",
		Role: entity.UserRole{
			Name: entity.RoleManager,
		},
	}

	c.authMock.EXPECT().User(gomock.Any(), "dev").Return(user, nil)

	client := entity.Client{
		ID:     uuid.Must(uuid.NewV4()),
		GUID:   uuid.Must(uuid.NewV4()),
		Name:   "Test name",
		INN:    "1234567890",
		OGRN:   "0987654321",
		Status: entity.ClientStatusApproved,
		Oferta: entity.ClientOferta{
			Status: entity.OfertaStatusSigned,
		},
		Employee: entity.Employee{
			Status: entity.EmployeeStatusActive,
			Role:   entity.EmployeeRoleAdmin,
		},
	}

	c.clientMock.EXPECT().UserClient(gomock.Any(), user.ID).Return(client, nil)

	requisites := entity.ClientRequisites{
		Name:                     "Test requisites company name",
		INN:                      "1234567890",
		KPP:                      "0987654321",
		Address:                  "Test requisites company address",
		BankBic:                  "0987654321",
		BankCorrespondentAccount: "0987654321",
		BankAccountNumber:        "0987654321",
		BankName:                 "Test requisites bank name",
	}

	c._1CMock.EXPECT().CreateBill(gomock.Any(), gomock.Any()).Return(requisites, nil)

	c.bankMock.EXPECT().OneTimeSPBLink(gomock.Any(), gomock.Any(), gomock.Any()).Return(entity.SPBLink{
		QrcID:   uuid.Must(uuid.NewV4()).String(),
		Payload: uuid.Must(uuid.NewV4()).String(),
		Status:  entity.SPBPaymentStatusStarted,
		Image: entity.Image{
			MediaType: "image/png",
			Content:   "AAAB35+g==",
		},
		OrderID:   uuid.Must(uuid.NewV4()).String(),
		RequestID: uuid.Must(uuid.NewV4()).String(),
	}, nil)

	req := payments.NewPostPaymentsSpbParams().WithCreateSPBLinkRequest(
		&models.APICreateSPBLinkRequest{
			Amount: 1500.25,
		})

	resp, err := c.api.PostPaymentsSpb(req, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.Code())
}

func TestHandler_CreateCardPayment(t *testing.T) {
	t.Parallel()

	c := NewClientAPI(t)

	user := entity.User{
		ID:        uuid.Must(uuid.NewV4()),
		FirstName: "Test first name",
		LastName:  "Test last name",
		Email:     uuid.Must(uuid.NewV4()).String() + "@example.com",
		Role: entity.UserRole{
			Name: entity.RoleManager,
		},
	}

	c.authMock.EXPECT().User(gomock.Any(), "dev").Return(user, nil)

	client := entity.Client{
		ID:     uuid.Must(uuid.NewV4()),
		GUID:   uuid.Must(uuid.NewV4()),
		Name:   "Test name",
		INN:    "1234567890",
		OGRN:   "0987654321",
		Status: entity.ClientStatusApproved,
		Oferta: entity.ClientOferta{
			Status: entity.OfertaStatusSigned,
		},
		Employee: entity.Employee{
			Status: entity.EmployeeStatusActive,
			Role:   entity.EmployeeRoleAdmin,
		},
	}

	c.clientMock.EXPECT().UserClient(gomock.Any(), user.ID).Return(client, nil)

	requisites := entity.ClientRequisites{
		Name:                     "Test requisites company name",
		INN:                      "1234567890",
		KPP:                      "0987654321",
		Address:                  "Test requisites company address",
		BankBic:                  "0987654321",
		BankCorrespondentAccount: "0987654321",
		BankAccountNumber:        "0987654321",
		BankName:                 "Test requisites bank name",
	}

	c._1CMock.EXPECT().CreateBill(gomock.Any(), gomock.Any()).Return(requisites, nil)

	cardPayment := entity.CardPayment{
		OrderID: uuid.Must(uuid.NewV4()),
		Link:    "https://" + uuid.Must(uuid.NewV4()).String() + ".example.com",
	}

	c.bankMock.EXPECT().CreateCardPayment(gomock.Any(), gomock.Any(), decimal.RequireFromString("1500.25"), gomock.Any()).
		Return(cardPayment, nil)

	req := payments.NewPostPaymentsCardParams().WithRequest(
		&models.APICreateCardPaymentRequest{
			Amount: 1500.25,
		})

	resp, err := c.api.PostPaymentsCard(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.Code())

	wantResp := &models.EntityCardPayment{
		Link:    cardPayment.Link,
		OrderID: cardPayment.OrderID.String(),
	}

	require.Equal(t, wantResp, resp.Payload.Payment)
}

func TestHandler_SBPCallback(t *testing.T) {
	t.Parallel()

	c := NewClientAPI(t)

	// Create test transaction to check invoice callback.
	now := time.Now().Truncate(time.Second)

	tx := entity.Transaction{
		ID:             uuid.Must(uuid.NewV4()),
		Name:           uuid.Must(uuid.NewV4()).String(),
		Number:         0, // Fill in by CreateTransaction method.
		ClientID:       uuid.Must(uuid.NewV4()),
		ClientGUID:     uuid.Must(uuid.NewV4()),
		Amount:         decimal.RequireFromString("1500.25"),
		TaxRatePercent: entity.DefaultTaxRatePercent,
		PaymentMethod:  entity.PaymentMethodSBP,
		Status:         entity.TransactionStatusCreated,
		QRCID:          uuid.Must(uuid.NewV4()).String(),
		CreatedBy:      uuid.Must(uuid.NewV4()),
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err := c.repo.CreateTransaction(context.Background(), tx)
	require.NoError(t, err)

	t.Run("paid status", func(t *testing.T) {
		t.Parallel()

		// Set producer expected call
		c.producerMock.EXPECT().SendUpdateBalance(gomock.Any(), tx.ID, tx.ClientID, tx.Amount)

		// Check invoice callback.
		req := payments.NewPostPaymentsCallbacksSbpParams().WithSBPCallbackRequest(
			&models.APISBPCallbackRequest{
				Status:    entity.SPBPaymentStatusPaid.String(),
				OrderID:   strconv.FormatInt(tx.Number, 10),
				RequestID: tx.ID.String(),
			},
		)
		resp, err := c.api.PostPaymentsCallbacksSbp(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.Code())

		// Check transaction status.
		gotTx, err := c.repo.Transaction(context.Background(), tx.ID)
		require.NoError(t, err)

		tx.Status = entity.TransactionStatusPaid // Check status change. )
		tx.UpdatedAt = gotTx.UpdatedAt
		tx.TaxRatePercent = 0 // Not stored in DB.

		require.Equal(t, tx, gotTx)
	})

	t.Run("not paid status", func(t *testing.T) {
		t.Parallel()

		req := payments.NewPostPaymentsCallbacksSbpParams().WithSBPCallbackRequest(
			&models.APISBPCallbackRequest{
				Status:    entity.SPBPaymentStatusNotStarted.String(),
				OrderID:   strconv.FormatInt(tx.Number, 10),
				RequestID: tx.ID.String(),
			},
		)
		resp, err := c.api.PostPaymentsCallbacksSbp(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.Code())
	})
}

func TestHandler_HealthHandler(t *testing.T) {
	t.Parallel()

	c := NewClientAPI(t)

	resp, err := c.apiHealth.GetHealth(health.NewGetHealthParams())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.Code())
}

func TestHandler_CardPaymentCallback(t *testing.T) {
	t.Parallel()

	c := NewClientAPI(t)

	// Create test transaction to check invoice callback.
	now := time.Now().Truncate(time.Second)

	tx := entity.Transaction{
		ID:             uuid.Must(uuid.NewV4()),
		ClientID:       uuid.Must(uuid.NewV4()),
		Number:         0, // Fill in by CreateTransaction method.
		ClientGUID:     uuid.Must(uuid.NewV4()),
		Amount:         decimal.RequireFromString("1500.25"),
		TaxRatePercent: entity.DefaultTaxRatePercent,
		PaymentMethod:  entity.PaymentMethodCard,
		Status:         entity.TransactionStatusCreated,
		CreatedBy:      uuid.Must(uuid.NewV4()),
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err := c.repo.CreateTransaction(context.Background(), tx)
	require.NoError(t, err)

	c.producerMock.EXPECT().SendUpdateBalance(gomock.Any(), tx.ID, tx.ClientID, tx.Amount)

	req := payments.NewGetPaymentsCallbacksCardParams().WithOrderNumber(tx.ID.String())

	resp, err := c.api.GetPaymentsCallbacksCard(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.Code())

	// Check transaction status.
	gotTx, err := c.repo.Transaction(context.Background(), tx.ID)
	require.NoError(t, err)
	require.Equal(t, entity.TransactionStatusPaid, gotTx.Status)
}

type Tester struct {
	apiHealth    health.ClientService
	api          payments.ClientService
	repo         *repository.Repository
	authMock     *mocks.MockAuthService
	clientMock   *mocks.MockClientService
	_1CMock      *mocks.Mock_1CService
	producerMock *mocks.MockProducer
	bankMock     *mocks.MockBankService
}

func NewClientAPI(t *testing.T) Tester {
	t.Helper()

	repo := newRepository(t)

	ctrl := gomock.NewController(t)
	authServiceMock := mocks.NewMockAuthService(ctrl)
	clientServiceMock := mocks.NewMockClientService(ctrl)
	_1CServiceMock := mocks.NewMock_1CService(ctrl)
	producerMock := mocks.NewMockProducer(ctrl)
	bankMock := mocks.NewMockBankService(ctrl)

	s := service.New(repo, clientServiceMock, _1CServiceMock, producerMock, bankMock)

	handler := api.NewHandler(s, false, nil)
	mw := api.NewMiddleware(authServiceMock, false, "dev", []string{})

	router := api.NewRouter(handler, mw)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	apiClient := payments.NewClientWithBearerToken(serverURL.Host, "/api", "http", "dev")
	apiHealthClient := health.NewClientWithBearerToken(serverURL.Host, "/api", "http", "dev")

	return Tester{
		api:          apiClient,
		apiHealth:    apiHealthClient,
		repo:         repo,
		authMock:     authServiceMock,
		clientMock:   clientServiceMock,
		_1CMock:      _1CServiceMock,
		producerMock: producerMock,
		bankMock:     bankMock,
	}
}

func newRepository(t *testing.T) *repository.Repository {
	t.Helper()

	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://postgres:dev@localhost:15432/postgres"
	}

	pool, err := postgres.Connect(context.Background(), dsn, 10)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	repo := repository.New(pool)

	return repo
}

func ptr[T any](v T) *T { //nolint:unused
	return &v
}
