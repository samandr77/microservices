package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/samandr77/microservices/payment/internal/entity"
)

//go:generate go run go.uber.org/mock/mockgen@latest -source=service.go -destination=../mocks/service.go -package=mocks -typed

type Repository interface {
	CreateTransaction(ctx context.Context, tx entity.Transaction) (entity.Transaction, error)
	TransactionByGUID(ctx context.Context, clientGUID uuid.UUID, number int64) (entity.Transaction, error)
	NotPaidTransactions(ctx context.Context, paymentMethod entity.PaymentMethod) ([]entity.Transaction, error)
	Transaction(ctx context.Context, id uuid.UUID) (entity.Transaction, error)
	UpdateTransactionStatus(ctx context.Context, id uuid.UUID, status entity.TransactionStatus, updatedAt time.Time) error
	UpdateTransactionQRCID(ctx context.Context, id uuid.UUID, qrcid string, updatedAt time.Time) error
	UpdateTransactionOrderID(ctx context.Context, id uuid.UUID, orderID uuid.UUID, updatedAt time.Time) error
	Transactions(ctx context.Context, clientID uuid.UUID, filter entity.TransactionFilter) ([]entity.Transaction, int, error)
	SaveInvoiceURL(ctx context.Context, billNumber int64, url string, updatedAt time.Time) error
	SetStatus(ctx context.Context, prevStatus, status entity.TransactionStatus, createdAtFrom time.Time) error
}

type ClientService interface {
	UserClient(ctx context.Context, userID uuid.UUID) (entity.Client, error)
	GetClientOwner(ctx context.Context, clientID uuid.UUID) (entity.ClientOwner, error)
}

type _1CService interface {
	CreateBill(ctx context.Context, i entity.Transaction) (entity.ClientRequisites, error)
}

type Producer interface {
	SendUpdateBalance(ctx context.Context, txID, clientID uuid.UUID, amount decimal.Decimal)
}

type BankService interface {
	OneTimeSPBLink(ctx context.Context, tx entity.Transaction, requisites entity.ClientRequisites) (entity.SPBLink, error)
	SPBPaymentStatus(ctx context.Context, txID uuid.UUID, qrcID string) (entity.SPBPaymentStatus, error)
	CreateCardPayment(ctx context.Context, txID uuid.UUID, amount decimal.Decimal, desc string) (entity.CardPayment, error)
	CardPaymentStatus(ctx context.Context, txID uuid.UUID) (entity.CardPaymentStatus, error)
}

type Service struct {
	repo     Repository
	client   ClientService
	_1C      _1CService
	producer Producer
	bank     BankService
}

func New(repo Repository, client ClientService, _1C _1CService, producer Producer, bank BankService) *Service {
	return &Service{
		repo:     repo,
		client:   client,
		_1C:      _1C,
		producer: producer,
		bank:     bank,
	}
}

func (s *Service) CreateInvoice(ctx context.Context, amount decimal.Decimal) (entity.Invoice, error) {
	user, err := entity.UserFromCtx(ctx)
	if err != nil {
		return entity.Invoice{}, err
	}

	client, err := s.client.UserClient(ctx, user.ID)
	if err != nil {
		return entity.Invoice{}, fmt.Errorf("get user %s client: %w", user, err)
	}

	err = validateClient(client)
	if err != nil {
		return entity.Invoice{}, fmt.Errorf("validate client: %w", err)
	}

	now := time.Now()

	tx := entity.Transaction{
		ID:             uuid.Must(uuid.NewV4()),
		ClientID:       client.ID,
		Number:         0, // Fill in by CreateTransaction method.
		ClientGUID:     client.GUID,
		Amount:         amount,
		TaxRatePercent: entity.DefaultTaxRatePercent,
		PaymentMethod:  entity.PaymentMethodInvoice,
		Status:         entity.TransactionStatusCreated,
		CreatedBy:      user.ID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err = s.repo.CreateTransaction(ctx, tx)
	if err != nil {
		return entity.Invoice{}, fmt.Errorf("create transaction: %w", err)
	}

	requisites, err := s._1C.CreateBill(ctx, tx)
	if err != nil {
		return entity.Invoice{}, fmt.Errorf("create bill: %w", err)
	}

	slog.InfoContext(ctx, fmt.Sprintf("Пополнение баланса организации %s методом: %q на сумму %s",
		tx.ClientID, entity.PaymentMethodInvoice, amount))

	return entity.Invoice{
		TxID:       tx.ID,
		Number:     tx.Number,
		PayerType:  entity.PayerTypeCompany,
		Service:    entity.ServiceDefault,
		Client:     client,
		Amount:     tx.Amount,
		Requisites: requisites,
	}, nil
}

func (s *Service) InvoicePaid(ctx context.Context, req entity.InvoiceCallback) error {
	tx, err := s.repo.TransactionByGUID(ctx, req.GUID, req.BillNumber)
	if err != nil {
		return fmt.Errorf("get transaction by guid %q and number %d: %w", req.GUID, req.BillNumber, err)
	}

	if tx.Status == entity.TransactionStatusPaid {
		return fmt.Errorf("transaction %q: %w", tx.ID, entity.ErrAlreadyPaid)
	}

	if tx.Amount.Cmp(req.TotalAmount) != 0 {
		return fmt.Errorf("%w: transaction %q amount %q is not equal to invoice callback amount %q",
			entity.ErrInvalidArgument, tx.ID, tx.Amount, req.TotalAmount)
	}

	err = s.repo.UpdateTransactionStatus(ctx, tx.ID, entity.TransactionStatusPaid, time.Now())
	if err != nil {
		return fmt.Errorf("update transaction %q status to %q: %w", tx.ID, entity.TransactionStatusPaid, err)
	}

	s.producer.SendUpdateBalance(ctx, tx.ID, tx.ClientID, tx.Amount)

	return nil
}

func (s *Service) CreateSPBLink(ctx context.Context, amount decimal.Decimal) (entity.SPBLink, error) {
	user, err := entity.UserFromCtx(ctx)
	if err != nil {
		return entity.SPBLink{}, err
	}

	client, err := s.client.UserClient(ctx, user.ID)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("get user %s client: %w", user, err)
	}

	err = validateClient(client)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("validate client: %w", err)
	}

	now := time.Now()

	tx := entity.Transaction{
		ID:             uuid.Must(uuid.NewV4()),
		ClientID:       client.ID,
		Number:         0, // Fill in by CreateTransaction method.
		ClientGUID:     client.GUID,
		Amount:         amount,
		TaxRatePercent: entity.DefaultTaxRatePercent,
		PaymentMethod:  entity.PaymentMethodSBP,
		Status:         entity.TransactionStatusCreated,
		CreatedBy:      user.ID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err = s.repo.CreateTransaction(ctx, tx)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("create transaction: %w", err)
	}

	requisites, err := s._1C.CreateBill(ctx, tx)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("create bill: %w", err)
	}

	spbLink, err := s.bank.OneTimeSPBLink(ctx, tx, requisites)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("create SPB link: %w", err)
	}

	err = s.repo.UpdateTransactionQRCID(ctx, tx.ID, spbLink.QrcID, time.Now())
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("update transaction %q QRC ID to %q: %w", tx.ID, spbLink.QrcID, err)
	}

	slog.InfoContext(ctx, fmt.Sprintf("Пополнение баланса организации %s методом: %q на сумму %s",
		tx.ClientID, entity.PaymentMethodSBP, amount))

	return spbLink, nil
}

func (s *Service) SBPPaid(ctx context.Context, txID uuid.UUID) error {
	tx, err := s.repo.Transaction(ctx, txID)
	if err != nil {
		return fmt.Errorf("get transaction %q: %w", txID, err)
	}

	if tx.Status == entity.TransactionStatusPaid {
		return fmt.Errorf("transaction %q: %w", tx.ID, entity.ErrAlreadyPaid)
	}

	err = s.repo.UpdateTransactionStatus(ctx, tx.ID, entity.TransactionStatusPaid, time.Now())
	if err != nil {
		return fmt.Errorf("update transaction %q status to %q: %w", tx.ID, entity.TransactionStatusPaid, err)
	}

	s.producer.SendUpdateBalance(ctx, tx.ID, tx.ClientID, tx.Amount)

	return nil
}

func (s *Service) CardPaymentPaid(ctx context.Context, txID uuid.UUID) error {
	tx, err := s.repo.Transaction(ctx, txID)
	if err != nil {
		return fmt.Errorf("get transaction %q: %w", txID, err)
	}

	if tx.Status == entity.TransactionStatusPaid {
		return fmt.Errorf("transaction %q: %w", tx.ID, entity.ErrAlreadyPaid)
	}

	err = s.repo.UpdateTransactionStatus(ctx, tx.ID, entity.TransactionStatusPaid, time.Now())
	if err != nil {
		return fmt.Errorf("update transaction %q status to %q: %w", tx.ID, entity.TransactionStatusPaid, err)
	}

	s.producer.SendUpdateBalance(ctx, tx.ID, tx.ClientID, tx.Amount)

	return nil
}

// validateClient for payment creation.
func validateClient(c entity.Client) error {
	if c.Status != entity.ClientStatusApproved {
		return fmt.Errorf("%w: client %s status is %q", entity.ErrClientNotApproved, c.ID, c.Status)
	}

	if c.Employee.Role != entity.EmployeeRoleAdmin {
		return fmt.Errorf("%w: employee %s role is %q, not %q", entity.ErrForbidden, c.Employee.ID, c.Employee.Role, entity.EmployeeRoleAdmin)
	}

	if c.Employee.Status != entity.EmployeeStatusActive {
		return fmt.Errorf("%w: employee %s status is %q, not %q",
			entity.ErrForbidden, c.Employee.ID, c.Employee.Status, entity.EmployeeStatusActive)
	}

	return nil
}

func (s *Service) UpdateSPBPaymentStatus(ctx context.Context) error {
	const maxWaitInterval = time.Hour * 24

	txs, err := s.repo.NotPaidTransactions(ctx, entity.PaymentMethodSBP)
	if err != nil {
		return fmt.Errorf("get not paid SPB transactions: %w", err)
	}

	var errs []error

	for _, tx := range txs {
		if tx.QRCID == "" {
			errs = append(errs, fmt.Errorf("transaction %q has no QRC ID", tx.ID))
			continue
		}

		if time.Since(tx.CreatedAt) > maxWaitInterval {
			continue
		}

		status, err := s.bank.SPBPaymentStatus(ctx, tx.ID, tx.QRCID)
		if err != nil {
			errs = append(errs, fmt.Errorf("get SPB payment status for transaction %q and QRC ID %q: %w", tx.ID, tx.QRCID, err))
			continue
		}

		if status == entity.SPBPaymentStatusPaid {
			err = s.repo.UpdateTransactionStatus(ctx, tx.ID, entity.TransactionStatusPaid, time.Now())
			if err != nil {
				errs = append(errs, fmt.Errorf("update transaction %q status to %q: %w", tx.ID, entity.TransactionStatusPaid, err))
				continue
			}

			s.producer.SendUpdateBalance(ctx, tx.ID, tx.ClientID, tx.Amount)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (s *Service) UpdateCardPaymentStatus(ctx context.Context) error {
	const maxWaitInterval = time.Hour * 24

	txs, err := s.repo.NotPaidTransactions(ctx, entity.PaymentMethodCard)
	if err != nil {
		return fmt.Errorf("get not paid SPB transactions: %w", err)
	}

	var errs []error

	for _, tx := range txs {
		if time.Since(tx.CreatedAt) > maxWaitInterval {
			continue
		}

		status, err := s.bank.CardPaymentStatus(ctx, tx.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("get SPB payment status for transaction %q and QRC ID %q: %w", tx.ID, tx.QRCID, err))
			continue
		}

		if status == entity.CardPaymentStatusAuthorizedCompleted {
			err = s.repo.UpdateTransactionStatus(ctx, tx.ID, entity.TransactionStatusPaid, time.Now())
			if err != nil {
				errs = append(errs, fmt.Errorf("update transaction %q status to %q: %w", tx.ID, entity.TransactionStatusPaid, err))
				continue
			}

			s.producer.SendUpdateBalance(ctx, tx.ID, tx.ClientID, tx.Amount)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (s *Service) Transactions(
	ctx context.Context,
	clientID uuid.UUID,
	filter entity.TransactionFilter,
) ([]entity.Transaction, int, error) {
	userFromContext, err := entity.UserFromCtx(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("get user from context: %w", err)
	}

	clientOwner, err := s.client.GetClientOwner(ctx, clientID)
	if err != nil {
		return nil, 0, fmt.Errorf("get client owner: %w", err)
	}

	if userFromContext.ID != clientOwner.ID && userFromContext.Role.Name != entity.RoleManager {
		return nil, 0, fmt.Errorf("%w: user %s is not owner", entity.ErrForbidden, userFromContext.ID)
	}

	txs, count, err := s.repo.Transactions(ctx, clientID, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("get transactions: %w", err)
	}

	return txs, count, nil
}

func (s *Service) CreateDebit(ctx context.Context, clientID, userID uuid.UUID, campaignName string, amount decimal.Decimal) error {
	userFromContext, err := entity.UserFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("get user from context: %w", err)
	}

	clientOwner, err := s.client.GetClientOwner(ctx, clientID)
	if err != nil {
		return fmt.Errorf("get client owner: %w", err)
	}

	if userFromContext.ID != clientOwner.ID && userFromContext.Role.Name != entity.RoleManager {
		return fmt.Errorf("%w: user %s is not manager or not owner", entity.ErrForbidden, userFromContext.ID)
	}

	now := time.Now()

	tx := entity.Transaction{
		ID:         uuid.Must(uuid.NewV4()),
		Name:       fmt.Sprintf("Списание денег по %q", campaignName),
		ClientID:   clientID,
		ClientGUID: uuid.Nil,
		Amount:     amount,
		Status:     entity.TransactionStatusPaid,
		CreatedBy:  userID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	_, err = s.repo.CreateTransaction(ctx, tx)
	if err != nil {
		return fmt.Errorf("create transaction: %w", err)
	}

	s.producer.SendUpdateBalance(ctx, tx.ID, tx.ClientID, tx.Amount)

	slog.InfoContext(ctx, fmt.Sprintf("Списание ДС организации %s на сумму %s", clientID, amount))

	return nil
}

func (s *Service) CreateCardPayment(ctx context.Context, amount decimal.Decimal) (entity.CardPayment, error) {
	user, err := entity.UserFromCtx(ctx)
	if err != nil {
		return entity.CardPayment{}, err
	}

	client, err := s.client.UserClient(ctx, user.ID)
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("get user %s client: %w", user, err)
	}

	err = validateClient(client)
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("validate client: %w", err)
	}

	now := time.Now()

	tx := entity.Transaction{
		ID:             uuid.Must(uuid.NewV4()),
		ClientID:       client.ID,
		Number:         0, // Fill in by CreateTransaction method.
		ClientGUID:     client.GUID,
		Amount:         amount,
		TaxRatePercent: entity.DefaultTaxRatePercent,
		PaymentMethod:  entity.PaymentMethodCard,
		Status:         entity.TransactionStatusCreated,
		CreatedBy:      user.ID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err = s.repo.CreateTransaction(ctx, tx)
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("create transaction: %w", err)
	}

	_, err = s._1C.CreateBill(ctx, tx)
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("create bill: %w", err)
	}

	paymentDesc := fmt.Sprintf("Оплата по счёту №%d от %s", tx.Number, tx.CreatedAt.Format("02.01.2006"))

	cardPayment, err := s.bank.CreateCardPayment(ctx, tx.ID, tx.Amount, paymentDesc)
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("create card payment: %w", err)
	}

	err = s.repo.UpdateTransactionOrderID(ctx, tx.ID, cardPayment.OrderID, time.Now())
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("update transaction %q order ID to %q: %w",
			tx.ID, cardPayment.OrderID, err)
	}

	slog.InfoContext(ctx, fmt.Sprintf("Пополнение баланса организации %s методом: %q на сумму %s",
		tx.ClientID, entity.PaymentMethodCard, amount))

	return cardPayment, nil
}

func (s *Service) SaveInvoiceURL(ctx context.Context, billNumber int64, url string) error {
	return s.repo.SaveInvoiceURL(ctx, billNumber, url, time.Now())
}

func (s *Service) Transaction(ctx context.Context, id uuid.UUID) (entity.Transaction, error) {
	tx, err := s.repo.Transaction(ctx, id)
	if err != nil {
		return entity.Transaction{}, fmt.Errorf("get tx %s: %w", id, err)
	}

	return tx, nil
}

func (s *Service) FailOldPayments(ctx context.Context) error {
	const maxWaitInterval = time.Hour * 24 * 7

	err := s.repo.SetStatus(ctx, entity.TransactionStatusCreated, entity.TransactionStatusFailed, time.Now().Add(-maxWaitInterval))
	if err != nil {
		return fmt.Errorf("fail old payments: %w", err)
	}

	return nil
}
