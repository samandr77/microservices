package entity

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type Client struct {
	ID        uuid.UUID
	GUID      uuid.UUID
	Name      string
	ShortName string
	INN       string
	KPP       string
	OGRN      string
	Status    ClientStatus
	Oferta    ClientOferta
	Employee  Employee
	Address   Address
}

type Address struct {
	Country string
	Region  string
	City    string
	Index   string
	Street  string
}

func (a Address) String() string {
	return a.Country + ", " + a.Region + ", " + a.City + ", " + a.Index + ", " + a.Street
}

type ClientOferta struct {
	Status OfertaStatus
}

type OfertaStatus string

const (
	OfertaStatusCreated OfertaStatus = "created"
	OfertaStatusSigned  OfertaStatus = "signed"
)

type EmployeeRole string

const (
	EmployeeRoleAdmin    EmployeeRole = "admin"
	EmployeeRoleObserver EmployeeRole = "observer"
)

type EmployeeStatus string

const (
	EmployeeStatusActive   EmployeeStatus = "active"
	EmployeeStatusInvited  EmployeeStatus = "invited"
	EmployeeStatusDeclined EmployeeStatus = "declined"
)

type Employee struct {
	ID              uuid.UUID      `json:"id"`
	Name            string         `json:"name"`
	Email           string         `json:"email"`
	Position        string         `json:"position"`
	Role            EmployeeRole   `json:"orgRole"`
	ClientID        uuid.UUID      `json:"clientID"`
	Status          EmployeeStatus `json:"status"`
	CreatedAt       time.Time      `json:"createdAt"`
	StatusChangedAt time.Time      `json:"statusChangedAt"`
	UserID          uuid.UUID      `json:"userID"`
}

type ClientRequisites struct {
	Name                     string `json:"name"`
	INN                      string `json:"inn"`
	KPP                      string `json:"kpp"`
	Address                  string `json:"address"`
	BankBic                  string `json:"bankBic"`
	BankCorrespondentAccount string `json:"bankCorrespondentAccount"`
	BankAccountNumber        string `json:"bankAccountNumber"`
	BankName                 string `json:"bankName"`
}

type ClientStatus string

const (
	ClientStatusApproved ClientStatus = "approved"
)

type ClientOwner struct {
	ID       uuid.UUID `json:"userID"`
	Name     string    `json:"name"`
	Email    string    `json:"email"`
	Position string    `json:"position"`
	OrgRole  string    `json:"orgRole"`
	ClientID uuid.UUID `json:"clientId"`
}
