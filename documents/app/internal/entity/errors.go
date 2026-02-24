package entity

import "errors"

var (
	ErrIncorrectRequestBody = errors.New("incorrect request body")
	ErrAlreadyExists        = errors.New("already exists")
	ErrNotFound             = errors.New("not found")
	ErrForbidden            = errors.New("forbidden")
)
