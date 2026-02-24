package entity

import (
	"errors"
)

var (
	ErrNotFound            = errors.New("not found")
	ErrInvalidArgument     = errors.New("invalid argument")
	ErrAlreadyPaid         = errors.New("already paid")
	ErrClientNotApproved   = errors.New("client not approved")
	ErrInvalidOfertaStatus = errors.New("invalid oferta status")
	ErrUnauthenticated     = errors.New("unauthenticated")
	ErrForbidden           = errors.New("forbidden")
)
