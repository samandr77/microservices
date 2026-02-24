package entity

import (
	"github.com/gofrs/uuid/v5"
	jwt "github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	IsFirstEnter bool      `json:"firstEnter"`
}

type UserInfo struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	LastName    string    `json:"lastName"`
	FirstName   string    `json:"firstName"`
	MiddleName  string    `json:"middleName"`
	PhoneNumber string    `json:"phoneNumber"`
	Role        UserRole  `json:"role"`
	Position    string    `json:"position"`
	IsBlocked   bool      `json:"isBlocked"`
	Status      string    `json:"status"`
}
type UserRole struct {
	ID   uuid.UUID `json:"role_id"`
	Name string    `json:"role_name"`
}

type UserJwtInfo struct {
	ID        uuid.UUID `json:"id"`
	Role      UserRole  `json:"role"`
	IsBlocked bool      `json:"isBlocked"`
}

type UserJwtClaims struct {
	User UserJwtInfo
	jwt.RegisteredClaims
}

type EmailSelectionRequired struct {
	Message string    `json:"message"`
	UserID  uuid.UUID `json:"user_id"`
	Emails  []string  `json:"email"`
}

type UpdateEmailRequest struct {
	Email  string `json:"email"`
	Sub    string `json:"sub"`
	SubAlt string `json:"sub_alt"`
}
