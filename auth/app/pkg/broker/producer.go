package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/segmentio/kafka-go"
)

type Producer struct {
	l                  *slog.Logger
	w                  *kafka.Writer
	notificationsTopic string
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
		l:                  l,
		w:                  w,
		notificationsTopic: topic,
	}
}

type SendEmailVerificationCodeEvent struct {
	Type       string   `json:"type"`
	Subject    string   `json:"subject"`
	Message    string   `json:"message"`
	Recipients []string `json:"recipients"`
}

func (p *Producer) SendEmailVerificationCode(ctx context.Context, email, code string) {
	event := SendEmailVerificationCodeEvent{
		Type:       "email",
		Subject:    "Код подтверждения для платформы БлагоДаря",
		Message:    "Ваш код подтверждения: " + code + "\n\nКод действителен в течение 2 минут.",
		Recipients: []string{email},
	}

	b, err := json.Marshal(event)
	if err != nil {
		p.l.Error(fmt.Sprintf("marshal event: %s", err))
		return
	}

	err = p.w.WriteMessages(ctx, kafka.Message{
		Key:   []byte(fmt.Sprintf("%s:%s", email, code)),
		Value: b,
		Topic: p.notificationsTopic,
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
