package entity

import (
	"github.com/gofrs/uuid/v5"
)

type CardPayment struct {
	OrderID uuid.UUID
	Link    string
}
