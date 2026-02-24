package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/segmentio/kafka-go"
)

type Consumer struct {
	l             *slog.Logger
	r             *kafka.Reader
	wg            *sync.WaitGroup
	topicHandlers map[string]func(context.Context, kafka.Message) error
}

func NewConsumer(
	brokers []string,
	groupID string,
	topics ...string,
) *Consumer {
	l := slog.Default().WithGroup("kafka").With("group_id", groupID)

	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     brokers,
		GroupID:     groupID,
		GroupTopics: topics,
		Logger:      &infoLogger{l: l},
		ErrorLogger: &errorLogger{l: l},
	})

	return &Consumer{
		l:             l,
		r:             r,
		wg:            &sync.WaitGroup{},
		topicHandlers: make(map[string]func(context.Context, kafka.Message) error),
	}
}

func (c *Consumer) Handle(topic string, handler func(context.Context, kafka.Message) error) *Consumer {
	c.topicHandlers[topic] = handler
	return c
}

func (c *Consumer) Consume(ctx context.Context) *Consumer {
	c.wg.Add(1)

	go func() {
		defer c.wg.Done()

		for {
			select {
			case <-ctx.Done():
				c.l.Info("context done")
				return
			default:
			}

			m, err := c.r.ReadMessage(ctx)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
			}

			handler, ok := c.topicHandlers[m.Topic]
			if !ok {
				c.l.Warn("kafka handler not found", "topic", m.Topic)
				continue
			}

			err = handler(ctx, m)
			if err != nil {
				c.l.Error(fmt.Sprintf("handler kafka msg: %s", err))
			}
		}
	}()

	return c
}

func (c *Consumer) Close() {
	err := c.r.Close()
	if err != nil {
		c.l.Error(fmt.Sprintf("close kafka reader: %s", err))
	}

	c.wg.Wait()
}

type infoLogger struct {
	l *slog.Logger
}

func (l *infoLogger) Printf(format string, v ...any) {
	l.l.Info(fmt.Sprintf(format, v...))
}

type errorLogger struct {
	l *slog.Logger
}

func (l *errorLogger) Printf(format string, v ...any) {
	l.l.Error(fmt.Sprintf(format, v...))
}
