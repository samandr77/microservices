package service

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/samandr77/microservices/auth/internal/entity"
)

const (
	EmailMaxLen        = 255
	NameMinLen         = 2
	NameMaxLen         = 50
	SberIDSubMaxLen    = 96
	SberIDAltSubMaxLen = 96
)

var (
	emailRegexp    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Zа-яА-Я0-9.-]+\.[a-zA-Zа-яА-Я]{2,}$`)
	cyrillicRegexp = regexp.MustCompile(`^[а-яёА-ЯЁ]+([\s-][а-яёА-ЯЁ]+)*$`)
)

func ValidateEmail(email string) error {
	if len(email) > EmailMaxLen {
		return entity.ErrEmailInvalidLen
	}

	if !emailRegexp.MatchString(email) {
		return entity.ErrEmailInvalidFormat
	}

	if strings.Contains(email, "..") {
		return entity.ErrEmailInvalidFormat
	}

	return nil
}

func ValidateName(name string) error {
	nameLen := utf8.RuneCountInString(name)
	if nameLen < NameMinLen || nameLen > NameMaxLen {
		return entity.ErrNameInvalidLen
	}

	if !cyrillicRegexp.MatchString(name) {
		return entity.ErrNameInvalidFormat
	}

	return nil
}

func NormalizeEmail(email string) (string, error) {
	normalized := strings.TrimSpace(email)

	normalized = strings.ToLower(normalized)

	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")
	normalized = strings.ReplaceAll(normalized, "[", "")
	normalized = strings.ReplaceAll(normalized, "]", "")
	normalized = strings.ReplaceAll(normalized, "<", "")
	normalized = strings.ReplaceAll(normalized, ">", "")

	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, "")

	err := ValidateEmail(normalized)
	if err != nil {
		return "", entity.ErrEmailNormalization
	}

	return normalized, nil
}

func ValidateSberIDSub(sub, subAlt string) error {
	if len(sub) > SberIDSubMaxLen {
		return errors.New("sub length exceeds 96 characters")
	}

	if len(subAlt) > SberIDAltSubMaxLen {
		return errors.New("sub_alt length exceeds 96 characters")
	}

	return nil
}
