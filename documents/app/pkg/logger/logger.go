package logger

import (
	"context"
	"log/slog"
	"os"
)

type ctxKey uint8

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyUserID
)

type Handler struct {
	slog.Handler
}

func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		record.Add("request_id", v)
	}

	if v, ok := ctx.Value(ctxKeyUserID).(string); ok {
		record.Add("user_id", v)
	}

	return h.Handler.Handle(ctx, record)
}

func New() *slog.Logger {
	l := slog.New(&Handler{slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})})

	slog.SetDefault(l)

	return l
}

func SetRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, reqID)
}

func SetUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}
