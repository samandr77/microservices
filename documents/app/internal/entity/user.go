package entity

import "github.com/gofrs/uuid/v5"

type UserRole struct {
	ID          uuid.UUID    `json:"role_id"`
	Name        string       `json:"role_name"`
	Permissions []Permission `json:"permissions"`
}

const (
	RoleManager = "manager"
	RoleUser    = "user"
	RoleSB      = "security personnel"
)

type Permission struct {
	ID   uuid.UUID `json:"permission_id"`
	Name string    `json:"permission_name"`
}

type User struct {
	ID          uuid.UUID `json:"id"`
	LastName    string    `json:"lastName"`
	FirstName   string    `json:"firstName"`
	MiddleName  string    `json:"middleName"`
	Email       string    `json:"email"`
	PhoneNumber string    `json:"phoneNumber"`
	Role        UserRole  `json:"role"`
	Position    string    `json:"position"`
	IsBlocked   bool      `json:"isBlocked"`
}
