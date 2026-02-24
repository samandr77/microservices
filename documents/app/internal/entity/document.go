package entity

import (
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

type DocType string

const (
	DocTypeOferta DocType = "oferta"
	DocTypeUPD    DocType = "upd"
)

type DocStatus string

const (
	DocStatusCreated DocStatus = "created"
	DocStatusSigned  DocStatus = "signed"
)

type Document struct {
	ID         uuid.UUID
	ClientID   uuid.UUID
	ClientName string
	Name       string
	DocType    DocType
	Status     DocStatus
	CreatedAt  time.Time
	SignedAt   *time.Time
	Sum        *decimal.Decimal
	URL        string
	Data       ClosingDocumentsData
	OneCGuid   uuid.UUID
}

type ClosingDocumentsRequestStatus string

const (
	RequestPending ClosingDocumentsRequestStatus = "pending"
	RequestDone    ClosingDocumentsRequestStatus = "done"
)

type ClosingDocumentsRequest struct {
	ID         uuid.UUID
	ClientID   uuid.UUID
	ClientName string
	Status     ClosingDocumentsRequestStatus
	OneCGuid   uuid.UUID
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type (
	ClosingDocuments struct {
		GUID uuid.UUID              `json:"guid"`
		URL  string                 `json:"url"`
		Data []ClosingDocumentsData `json:"data"`
	}

	ClosingDocumentsData struct {
		ActInfo      ActInfo        `json:"actInfo"`
		InvoiceInfo  InvoiceInfo    `json:"invoiceInfo"`
		Occassion    string         `json:"occassion"`
		ServicesList []ServicesList `json:"servicesList"`
	}

	ActInfo struct {
		ActNumber string    `json:"actNumber"`
		ActDate   time.Time `json:"actDate"`
	}

	InvoiceInfo struct {
		InvoiceNumber string    `json:"invoiceNumber"`
		InvoiceDate   time.Time `json:"invoiceDate"`
	}

	ServicesList struct {
		Name        string          `json:"name"`
		Amount      string          `json:"amount"`
		Units       string          `json:"units"`
		UnitPrice   decimal.Decimal `json:"unitPrice"`
		TaxRate     string          `json:"taxRate"`
		TaxAmount   decimal.Decimal `json:"taxAmount"`
		TotalAmount decimal.Decimal `json:"totalAmount"`
	}
)

type DownloadedDocument struct {
	Name string
	Data []byte
}

type DocumentsSortBy string

func (d DocumentsSortBy) String() string {
	return string(d)
}

func (d DocumentsSortBy) IsValid() bool {
	switch d {
	case SortByName, SortByCreatedAt, SortByDocType:
		return true
	default:
		return false
	}
}

const (
	SortByName      DocumentsSortBy = "name"
	SortByCreatedAt DocumentsSortBy = "created_at"
	SortByDocType   DocumentsSortBy = "doc_type"
)

type OrderBy string

func (o OrderBy) String() string {
	return string(o)
}

func (o OrderBy) IsValid() bool {
	switch o {
	case ASC, DESC:
		return true
	default:
		return false
	}
}

const (
	ASC  OrderBy = "asc"
	DESC OrderBy = "desc"
)

type DocumentsFilter struct {
	ClientID uuid.UUID
	Page     uint64
	Limit    uint64
	SortBy   DocumentsSortBy
	OrderBy  OrderBy
}
