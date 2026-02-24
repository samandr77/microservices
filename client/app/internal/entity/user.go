package entity

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type UserStatus string

const (
	UserStatusActive  UserStatus = "active"
	UserStatusBlocked UserStatus = "blocked"
	UserStatusDeleted UserStatus = "deleted"
)

const (
	ActionViewPublicInfo = "view_public_info"
	ActionRestoreAccount = "restore_account"
)

type VerificationStatus string

const (
	VerificationStatusUnverified VerificationStatus = "unverified"
	VerificationStatusPending    VerificationStatus = "pending"
	VerificationStatusVerified   VerificationStatus = "verified"
)

type User struct {
	UserID                uuid.UUID          `json:"user_id"`
	Sub                   *string            `json:"sub,omitempty"`
	SubAlt                *string            `json:"sub_alt,omitempty"`
	LastName              *string            `json:"last_name,omitempty"`
	FirstName             *string            `json:"first_name,omitempty"`
	MiddleName            *string            `json:"middle_name,omitempty"`
	Email                 string             `json:"email"`
	Phone                 *string            `json:"phone,omitempty"`
	Birthdate             *string            `json:"birthdate,omitempty"`
	City                  *string            `json:"city,omitempty"`
	SchoolName            *string            `json:"school_name,omitempty"`
	PlaceOfEducation      *string            `json:"place_of_education,omitempty"`
	AddressReg            *string            `json:"address_reg,omitempty"`
	Series                *string            `json:"series,omitempty"`
	Number                *string            `json:"number,omitempty"`
	IssuedBy              *string            `json:"issued_by,omitempty"`
	IssuedDate            *string            `json:"issued_date,omitempty"`
	Code                  *string            `json:"code,omitempty"`
	PersonalInfo          *string            `json:"personal_info,omitempty"`
	RoleID                uuid.UUID          `json:"role_id"`
	Status                UserStatus         `json:"status"`
	VerificationStatus    VerificationStatus `json:"verification_status"`
	PrivacyPolicyAgreed   bool               `json:"privacy_policy_agreed"`
	NewsletterAgreed      bool               `json:"newsletter_agreed"`
	PublicDonationsAgreed bool               `json:"public_donations_agreed"`
	CreatedAt             time.Time          `json:"created_at"`
	UpdatedAt             time.Time          `json:"updated_at"`
	DeletedAt             *time.Time         `json:"deleted_at,omitempty"`
}

func (s UserStatus) IsValid() bool {
	switch s {
	case UserStatusActive, UserStatusBlocked, UserStatusDeleted:
		return true
	}

	return false
}

func (u *User) CanPerformAction(action string) bool {
	switch u.Status {
	case UserStatusActive:
		return true
	case UserStatusBlocked:
		return action == ActionViewPublicInfo
	case UserStatusDeleted:
		return action == ActionViewPublicInfo || action == ActionRestoreAccount
	}

	return false
}
