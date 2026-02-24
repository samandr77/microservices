package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/samandr77/microservices/notification/internal/entity"
)

type Service interface {
	SendMessage(message entity.Message) error
}

type Handler struct {
	s Service
}

func NewHandler(s Service) *Handler {
	return &Handler{
		s: s,
	}
}

// @Summary Проверка состояния сервера
// @Description Возвращает статус работы сервера.
// @Tags health
// @Success 200 {string} string "Сервер работает!"
// @Router  /api/health [get]
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("Сервер работает!\n"))
}

type SendMessageRequest struct {
	Type        string   `json:"type"`
	Subject     string   `json:"subject"`
	Message     string   `json:"message"`
	Recipients  []string `json:"recipients"`
	ContentType string   `json:"contentType"` // новый параметр
}

// @Summary Отправка сообщения
// @Description Отправляет сообщение пользователям.
// @Tags messages
// @Accept json
// @Produce json
// @Param request body SendMessageRequest true "структура сообщения"
// @Failure 400 {object} ResponseError "Некорректное тело запроса"
// @Failure 500 {object} ResponseError "Не удалось отправить сообщение"
// @Router /api/messages [post]
func (h *Handler) SendMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var msg SendMessageRequest
	err := json.NewDecoder(r.Body).Decode(&msg)

	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	entityMsg := entity.Message{
		Type:        msg.Type,
		Subject:     msg.Subject,
		Message:     msg.Message,
		Recipients:  msg.Recipients,
		ContentType: msg.ContentType,
	}

	err = h.s.SendMessage(entityMsg)
	if err != nil {
		if errors.Is(err, entity.ErrUnknownMessageType) {
			SendErr(ctx, w, http.StatusBadRequest, err, "Неизвестный тип сообщения")
			return
		}

		SendErr(ctx, w, http.StatusInternalServerError, err, fmt.Sprintf("Не удалось отправить сообщение: %s", err.Error()))
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Сообщение успешно отправлено"))
}
