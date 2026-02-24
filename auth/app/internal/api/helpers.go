package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/internal/service"
)

const errInternalRuText = "Внутренняя ошибка"

type ResponseError struct {
	Message   string     `json:"message"`
	BlockedTo *time.Time `json:"blocked_to,omitempty"`
}

func sendErr(ctx context.Context, w http.ResponseWriter, code int, err error, msg string) {
	// Структурированное логирование с msg как основным сообщением
	slog.ErrorContext(ctx, msg, "error", err.Error(), "http_code", code)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	// Кодирование специальных символов выполняется автоматически json.Encoder
	err = json.NewEncoder(w).Encode(ResponseError{
		Message: msg,
	})
	if err != nil {
		slog.ErrorContext(ctx, "failed to encode error response",
			"error", err.Error(),
			"http_code", http.StatusInternalServerError)
	}
}

func sendJSON(ctx context.Context, w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		sendErr(ctx, w, http.StatusInternalServerError, err, errInternalRuText)
		return
	}
}

func emailErrRuText(err error) string {
	switch {
	case errors.Is(err, entity.ErrEmailInvalidFormat):
		return "E-mail может содержать только латинские буквы, цифры и знаки \"+\", \"-\", \".\""
	case errors.Is(err, entity.ErrEmailInvalidLen):
		return fmt.Sprintf("Длина e-mail не должна превышать %d знаков", service.EmailMaxLen)
	default:
		return errInternalRuText
	}
}

func nameErrRuText(err error) string {
	switch {
	case errors.Is(err, entity.ErrNameInvalidFormat):
		return "Имя и фамилия могут содержать только буквы русского алфавита"
	case errors.Is(err, entity.ErrNameInvalidLen):
		return "Имя и фамилия не могут быть пустыми"
	default:
		return errInternalRuText
	}
}

func blockErrRuText(err error) string { //nolint:unused
	switch {
	case errors.Is(err, entity.ErrUserBlocked):
		return "Аккаунт заблокирован. Обратитесь в поддержку"
	case errors.Is(err, entity.ErrUserDeleted):
		return "Аккаунт удалён. Для восстановления обратитесь в поддержку"
	case errors.Is(err, entity.ErrTooManyAttempts):
		return "Слишком много попыток. Попробуйте позже"
	default:
		return errInternalRuText
	}
}

const (
	sberIDServiceUnavailableRuText = "Сервис Сбер ID временно недоступен, попробуйте позже"
	sberIDInvalidCredentialsRuText = "Неверные учетные данные для Сбер ID" //nolint:gosec // not a credential, just error message
	sberIDRateLimitRuText          = "Превышен лимит запросов к Сбер ID, попробуйте позже"
	sberIDForbiddenRuText          = "Доступ запрещён. Проверьте сертификат"
)

func sberIDErrRuText(err error) string {
	switch {
	case errors.Is(err, entity.ErrSberIDInvalidCode):
		return "Неверный код авторизации Сбер ID"
	case errors.Is(err, entity.ErrSberIDCodeExpired):
		return "Код авторизации истек, попробуйте войти заново"
	case errors.Is(err, entity.ErrSberIDInvalidClient):
		return sberIDInvalidCredentialsRuText
	case errors.Is(err, entity.ErrSberIDInvalidRequest):
		return "Неверные параметры запроса"
	case errors.Is(err, entity.ErrSberIDInvalidNonce):
		return "Неверный параметр nonce"
	case errors.Is(err, entity.ErrSberIDInvalidAccessToken):
		return "Неверный токен доступа Сбер ID"
	case errors.Is(err, entity.ErrSberIDAccessTokenExpired):
		return "Токен доступа истек"
	case errors.Is(err, entity.ErrSberIDScopeInsufficient):
		return "Недостаточно прав доступа"
	case errors.Is(err, entity.ErrSberIDRateLimitExceeded):
		return sberIDRateLimitRuText
	case errors.Is(err, entity.ErrSberIDForbidden):
		return sberIDForbiddenRuText
	case errors.Is(err, entity.ErrSberIDNotFound):
		return "Ресурс не найден"
	case errors.Is(err, entity.ErrSberIDServiceUnavailable):
		return sberIDServiceUnavailableRuText
	default:
		return errInternalRuText
	}
}
