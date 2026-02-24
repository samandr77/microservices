package entity

import "errors"

var (
	ErrUnauthorized            = errors.New("unauthorized")
	ErrForbidden               = errors.New("forbidden")
	ErrUserBlocked             = errors.New("user is blocked")
	ErrUserDeleted             = errors.New("user is deleted")
	ErrUserNotFound            = errors.New("user not found")
	ErrInvalidStatus           = errors.New("invalid user status")
	ErrBlockNotFound           = errors.New("user block not found")
	ErrCannotChangeStatus      = errors.New("cannot change status")
	ErrTemporaryBlocksExceeded = errors.New("temporary blocks limit exceeded")
	ErrRestorePeriodExpired    = errors.New("restore period expired")
	ErrDuplicateEmail          = errors.New("email already exists")
	ErrDuplicateSub            = errors.New("sub already exists")
	ErrDuplicateSubAlt         = errors.New("sub_alt already exists")
	ErrInvalidEmail            = errors.New("invalid email format")
	ErrInvalidPhone            = errors.New("invalid phone format")
	ErrInvalidBirthdate        = errors.New("invalid birthdate")
	ErrInvalidName             = errors.New("invalid name format")
	ErrMissingRequiredField    = errors.New("missing required field")
	ErrValidationFailed        = errors.New("validation failed")
	ErrUserAlreadyBlocked      = errors.New("user is already blocked")
	ErrUserAlreadyActive       = errors.New("user is already active")
	ErrCannotUnblockTemporary  = errors.New("cannot manually unblock temporary block")
	ErrPermissionDenied        = errors.New("permission denied")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrInvalidTextField        = errors.New("invalid text field")
	ErrInvalidPassportSeries   = errors.New("invalid passport series")
	ErrInvalidPassportNumber   = errors.New("invalid passport number")
	ErrInvalidPassportCode     = errors.New("invalid passport code")
	ErrInvalidIssuedDate       = errors.New("invalid issued date")
	ErrInvalidCity             = errors.New("invalid city")
	ErrInvalidSchoolName       = errors.New("invalid school name")
	ErrInvalidPlaceOfEducation = errors.New("invalid place of education")
	ErrInvalidAddress          = errors.New("invalid address")
	ErrPrivacyPolicyRequired   = errors.New("privacy policy agreement required")
	ErrTokenDestroyFailed      = errors.New("failed to destroy user tokens")
)

const (
	ErrMsgInternal       = "Внутренняя ошибка сервера"
	ErrMsgBadRequest     = "Некорректный запрос"
	ErrMsgInvalidData    = "Недопустимые данные"
	ErrMsgInvalidRequest = "Неверный запрос"
	ErrMsgValidation     = "Ошибка валидации"
	ErrMsgEmailTaken     = "Email уже занят"
	ErrMsgSubTaken       = "Сбер ID уже используется"
	ErrMsgSubAltTaken    = "Альтернативный Сбер ID уже используется"
	ErrMsgNotFound       = "Пользователь не найден"
	ErrMsgUnauthorized   = "Требуется аутентификация"
)
