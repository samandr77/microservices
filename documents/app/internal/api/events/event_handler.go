package events

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/gofrs/uuid/v5"
	"github.com/segmentio/kafka-go"
	"github.com/shopspring/decimal"
)

type Service interface {
	SignOferta(ctx context.Context, clientID uuid.UUID) error
}

type EventHandler struct {
	s Service
}

func NewEventHandler(s Service) *EventHandler {
	return &EventHandler{s: s}
}

type OnBalanceUpdatedEvent struct {
	TxID     uuid.UUID       `json:"tx_id"`
	ClientID uuid.UUID       `json:"client_id"`
	Amount   decimal.Decimal `json:"amount"`
}

func (h *EventHandler) OnBalanceUpdated(ctx context.Context, msg kafka.Message) error {
	var event OnBalanceUpdatedEvent

	err := json.Unmarshal(msg.Value, &event)
	if err != nil {
		return fmt.Errorf("unmarshal event: %w", err)
	}

	if event.Amount.LessThanOrEqual(decimal.Zero) {
		return nil
	}

	err = h.s.SignOferta(ctx, event.ClientID)
	if err != nil {
		return fmt.Errorf("update balance: %w", err)
	}

	return nil
}
