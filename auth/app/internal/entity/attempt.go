package entity

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type AttemptType string

const (
	AttemptTypeAuth     AttemptType = "auth"
	AttemptTypeRegister AttemptType = "register"
)

type ProviderType string

const (
	ProviderTypeEmail  ProviderType = "email"
	ProviderTypeSberID ProviderType = "sber_id"
)

type Attempt struct {
	ID        uuid.UUID
	Type      AttemptType
	UserID    *uuid.UUID
	Provider  ProviderType
	Email     string
	IPAddress string
	CodeHash  string
	CreatedAt time.Time
}

type AttemptBlock struct {
	ID         uuid.UUID
	Type       string
	Email      string
	IPAddress  string
	StartBlock time.Time
	EndBlock   time.Time
}
