package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/segmentio/kafka-go"
	"github.com/samandr77/microservices/notification/internal/entity"
)

type Service interface {
	SendMessage(message entity.Message) error
}

type EventHandler struct {
	s Service
}

func NewEventHandler(s Service) *EventHandler {
	return &EventHandler{s: s}
}

type SendEmailVerificationCodeEvent struct {
	Type       string   `json:"type"`
	Subject    string   `json:"subject"`
	Message    string   `json:"message"`
	Recipients []string `json:"recipients"`
}

func (h *EventHandler) SendVerificationCode(_ context.Context, msg kafka.Message) error {
	var event SendEmailVerificationCodeEvent

	err := json.Unmarshal(msg.Value, &event)
	if err != nil {
		return fmt.Errorf("unmarshal event: %w", err)
	}

	err = h.s.SendMessage(entity.Message{
		Type:       event.Type,
		Subject:    event.Subject,
		Message:    event.Message,
		Recipients: event.Recipients,
	})
	if err != nil {
		return fmt.Errorf("update balance: %w", err)
	}

	return nil
}
