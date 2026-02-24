package logger

import (
	"context"
	"log/slog"
	"os"

	"github.com/gofrs/uuid/v5"
)

type ctxKey int8

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyClientID
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

func New(level string) (*slog.Logger, error) {
	var sLevel slog.Level

	err := sLevel.UnmarshalText([]byte(level))
	if err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{
		Level: sLevel,
	}

	l := slog.New(&Handler{slog.NewJSONHandler(os.Stdout, opts)})

	slog.SetDefault(l)

	return l, nil
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, requestID)
}

func WithUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

func RequestIDFromCtx(ctx context.Context) string {
	requestID, ok := ctx.Value(ctxKeyRequestID).(string)
	if !ok {
		return ""
	}

	return requestID
}
