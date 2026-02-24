package entity

import (
	"fmt"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

type TransactionFilter struct {
	ID        *string
	Amount    *string
	CreatedAt *string
	Page      uint64
	Limit     uint64
	SortBy    TransactionSortCol
	OrderBy   OrderByCol
}

type TransactionSortCol string

func (t TransactionSortCol) String() string {
	return string(t)
}

const (
	SortByID        TransactionSortCol = "id"
	SortByAmount    TransactionSortCol = "amount"
	SortByCreatedAt TransactionSortCol = "created_at"
)

func (t TransactionSortCol) IsValid() bool {
	switch t {
	case SortByID, SortByAmount, SortByCreatedAt:
		return true
	}

	return false
}

type OrderByCol string

func (o OrderByCol) String() string {
	return string(o)
}

const (
	DESC OrderByCol = "desc"
	ASC  OrderByCol = "asc"
)

func (o OrderByCol) IsValid() bool {
	switch o {
	case DESC, ASC:
		return true
	}

	return false
}

const (
	DefaultTaxRatePercent uint32 = 20
)

type TransactionStatus string

const (
	TransactionStatusCreated TransactionStatus = "CREATED"
	TransactionStatusPaid    TransactionStatus = "PAID"
	TransactionStatusFailed  TransactionStatus = "FAILED"
)

func (t TransactionStatus) String() string {
	return string(t)
}

type PaymentMethod string

const (
	PaymentMethodCard    PaymentMethod = "CARD"
	PaymentMethodSBP     PaymentMethod = "SBP"
	PaymentMethodInvoice PaymentMethod = "INVOICE"
)

func (p PaymentMethod) Validate() error {
	switch p {
	case PaymentMethodCard, PaymentMethodSBP, PaymentMethodInvoice:
		return nil
	default:
		return fmt.Errorf("%w: unknown payment method %s", ErrInvalidArgument, p)
	}
}

func (p PaymentMethod) String() string {
	return string(p)
}

type Transaction struct {
	ID             uuid.UUID
	Name           string
	Number         int64 // Used as a global unique bill number in 1C. Filled by our DB.
	ClientID       uuid.UUID
	ClientGUID     uuid.UUID
	Amount         decimal.Decimal
	TaxRatePercent uint32
	PaymentMethod  PaymentMethod
	Status         TransactionStatus
	QRCID          string // QR code ID, only for PaymentMethodSBP
	InvoiceURL     string // Invoice s3 URL, only for PaymentMethodInvoice
	CreatedBy      uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type InvoiceCallback struct {
	GUID        uuid.UUID       `json:"guid"`
	BillNumber  int64           `json:"billNumber"`
	BillDate    time.Time       `json:"billDate"`
	TotalAmount decimal.Decimal `json:"totalAmount"`
}

// TaxAmount returns the tax amount by formula: amount * taxRatePercent / 100 and truncates to 2 decimal places.
//
//nolint:mnd
func (i Transaction) TaxAmount() decimal.Decimal {
	if i.TaxRatePercent == 0 {
		return decimal.NewFromInt(0)
	}

	taxPercent := decimal.New(int64(i.TaxRatePercent), 0)
	oneHundred := decimal.New(100, 0)

	taxAmount := i.Amount.Mul(taxPercent).Div(oneHundred)
	rounded := taxAmount.Round(2)

	return rounded
}
