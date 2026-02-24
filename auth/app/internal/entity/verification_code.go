package entity

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type VerificationAction string

const (
	VerificationActionRegister VerificationAction = "register"
	VerificationActionAuth     VerificationAction = "auth"
)

type VerificationCode struct {
	ID                    uuid.UUID
	Email                 string
	Action                VerificationAction
	CodeHash              string
	IsUsed                bool
	ExpirationDate        time.Time
	CreatedAt             time.Time
	FirstName             *string
	LastName              *string
	PrivacyPolicyAgreed   *bool
	NewsletterAgreed      *bool
	PublicDonationsAgreed *bool
}

func (vc *VerificationCode) Validate(email string) error {
	if vc.IsUsed {
		return ErrCodeAlreadyUsed
	}

	if vc.Email != email {
		return ErrCodeInvalid
	}

	if !vc.ExpirationDate.After(time.Now()) {
		return ErrCodeExpired
	}

	return nil
}
