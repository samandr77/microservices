package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/gofrs/uuid/v5"
	"github.com/segmentio/kafka-go"
	"github.com/shopspring/decimal"
)

type Producer struct {
	l                   *slog.Logger
	w                   *kafka.Writer
	balanceUpdatedTopic string
}

func NewProducer(l *slog.Logger, brokers []string, topic string) *Producer {
	l = l.WithGroup("kafka").With("topic", topic)

	w := &kafka.Writer{
		Addr:                   kafka.TCP(brokers...),
		Topic:                  "",
		Balancer:               &kafka.LeastBytes{},
		Async:                  true,
		Compression:            0,
		Logger:                 &infoLogger{l: l},
		ErrorLogger:            &errorLogger{l: l},
		AllowAutoTopicCreation: true,
	}

	return &Producer{
		l:                   l,
		w:                   w,
		balanceUpdatedTopic: topic,
	}
}

type SendUpdateBalanceEvent struct {
	TxID     uuid.UUID       `json:"tx_id"`
	ClientID uuid.UUID       `json:"client_id"`
	Amount   decimal.Decimal `json:"amount"`
}

func (p *Producer) SendUpdateBalance(ctx context.Context, txID, clientID uuid.UUID, amount decimal.Decimal) {
	event := SendUpdateBalanceEvent{
		TxID:     txID,
		ClientID: clientID,
		Amount:   amount,
	}

	b, err := json.Marshal(event)
	if err != nil {
		p.l.Error(fmt.Sprintf("marshal event: %s", err))
		return
	}

	err = p.w.WriteMessages(ctx, kafka.Message{
		Key:   []byte(txID.String()),
		Value: b,
		Topic: p.balanceUpdatedTopic,
	})
	if err != nil {
		p.l.Error(fmt.Sprintf("write kafka message: %s", err))
		return
	}
}

func (p *Producer) Close() {
	err := p.w.Close()
	if err != nil {
		p.l.Error(fmt.Sprintf("close kafka writer: %s", err))
	}
}
