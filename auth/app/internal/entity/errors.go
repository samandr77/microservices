package entity

import (
	"errors"
	"time"

	"github.com/gofrs/uuid/v5"
)

var (
	ErrUserBlocked            = errors.New("user is blocked")
	ErrUserNotFound           = errors.New("user not found")
	ErrUserDeleted            = errors.New("user deleted")
	ErrInvalidToken           = errors.New("invalid token")
	ErrAlreadyExists          = errors.New("already exists")
	ErrNotFound               = errors.New("not found")
	ErrUnauthorized           = errors.New("unauthorized")
	ErrManyAttempts           = errors.New("many attempts")
	ErrAttemptTimerNotExpired = errors.New("the timer has not expired")
)

var (
	ErrCodeInvalid     = errors.New("invalid code")
	ErrCodeExpired     = errors.New("expired code")
	ErrCodeAlreadyUsed = errors.New("code is already used")
)

var (
	ErrPasswordInvalidLen    = errors.New("password must be from 8 to 12 symbols")
	ErrPasswordNoUpperCase   = errors.New("password must contains minimum one upper-case letter")
	ErrPasswordNoDigit       = errors.New("password must contains minimum one digit")
	ErrPasswordNoSpecialChar = errors.New("password must contains minimum one special character")
)

var (
	ErrEmailInvalidLen    = errors.New("email length exceeds 255 characters")
	ErrEmailInvalidFormat = errors.New("incorrect email format")
)

var (
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenInvalid     = errors.New("invalid token")
	ErrRefreshTokenUsed = errors.New("refresh token already used")
	ErrTokenNotFound    = errors.New("token not found")
	ErrTokenRevoked     = errors.New("token revoked")
)

var (
	ErrUserBlockedTemporary = errors.New("user temporarily blocked")
	ErrUserBlockedPermanent = errors.New("user permanently blocked")
	ErrIPBlocked            = errors.New("IP address blocked")
	ErrTooManyRequests      = errors.New("too many requests")
	ErrTooManyAttempts      = errors.New("too many attempts")
)

var (
	ErrNameInvalidFormat     = errors.New("name contains invalid characters")
	ErrNameInvalidLen        = errors.New("name must be between 2 and 50 characters")
	ErrLastNameInvalidFormat = errors.New("last name contains invalid characters")
	ErrEmailNormalization    = errors.New("email normalization failed")
)

type BlockedError struct {
	BlockedTo *time.Time
}

func (e *BlockedError) Error() string { return ErrUserBlocked.Error() }

var (
	ErrSberIDInvalidCode       = errors.New("invalid authorization code")
	ErrSberIDCodeExpired       = errors.New("authorization code expired")
	ErrSberIDInvalidClient     = errors.New("invalid client credentials")
	ErrSberIDInvalidRequest    = errors.New("invalid request parameters")
	ErrSberIDScopeInsufficient = errors.New("insufficient scope permissions")

	ErrSberIDInvalidAccessToken = errors.New("invalid access token")
	ErrSberIDAccessTokenExpired = errors.New("access token expired")

	ErrSberIDInvalidNonce = errors.New("invalid nonce parameter")

	ErrSberIDRateLimitExceeded  = errors.New("rate limit exceeded")
	ErrSberIDServiceUnavailable = errors.New("sber id service unavailable")
	ErrSberIDForbidden          = errors.New("access forbidden - check certificate")
	ErrSberIDNotFound           = errors.New("resource not found")
)

type EmailSelectionError struct {
	UserID uuid.UUID
	Emails []string
}

func (e *EmailSelectionError) Error() string {
	return "email selection required"
}
