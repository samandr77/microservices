package entity

import (
	"github.com/gofrs/uuid/v5"
)

type User struct {
	ID        uuid.UUID
	FirstName string
	LastName  string
	Email     string
	Role      UserRole
}

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
