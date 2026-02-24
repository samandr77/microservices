package entity

import (
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

type PayerType = string

const (
	PayerTypeCompany PayerType = "Юридическое лицо"
)

// Service is a kind of service that the client pays for
type Service = string

const (
	ServiceDefault = "Оплата услуг"
)

type Invoice struct {
	TxID       uuid.UUID
	Number     int64
	PayerType  PayerType
	Service    Service
	Client     Client
	Amount     decimal.Decimal
	Requisites ClientRequisites
}
