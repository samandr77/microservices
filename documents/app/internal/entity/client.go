package entity

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type Client struct {
	ID        uuid.UUID
	Name      string
	INN       string
	Status    string
	OneCGuid  uuid.UUID
	CreatedAt time.Time
}

type ClientOwner struct {
	ID       uuid.UUID `json:"userID"`
	Name     string    `json:"name"`
	Email    string    `json:"email"`
	Position string    `json:"position"`
	OrgRole  string    `json:"orgRole"`
	ClientID uuid.UUID `json:"clientId"`
}
