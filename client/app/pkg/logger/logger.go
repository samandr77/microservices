package logger

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/samandr77/microservices/client/internal/entity"
)

type ctxKey uint8

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyUserID
	ctxKeyCallerService
	ctxKeyMethod
	ctxKeyLogType
	ctxKeyIP
	ctxKeyURL
	ctxKeyDeviceID
	ctxKeyUserAgent
)

const originService = "blago-user"

type Handler struct {
	slog.Handler
}

func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok && v != "" {
		record.Add("request_id", v)
	}

	if v, ok := ctx.Value(ctxKeyUserID).(string); ok && v != "" {
		record.Add("user_id", v)
	} else {
		record.Add("user_id", nil)
	}

	if v, ok := ctx.Value(ctxKeyIP).(string); ok && v != "" {
		record.Add("ip", v)
	}

	if v, ok := ctx.Value(ctxKeyMethod).(string); ok && v != "" {
		record.Add("method", v)
	}

	if v, ok := ctx.Value(ctxKeyURL).(string); ok && v != "" {
		record.Add("url", v)
	}

	if v, ok := ctx.Value(ctxKeyDeviceID).(string); ok && v != "" {
		record.Add("device_id", v)
	}

	if v, ok := ctx.Value(ctxKeyUserAgent).(string); ok && v != "" {
		record.Add("useragent", v)
	}

	if v, ok := ctx.Value(ctxKeyLogType).(string); ok && v != "" {
		record.Add("type", v)
	}

	if v, ok := ctx.Value(ctxKeyCallerService).(string); ok && v != "" {
		record.Add("caller_service", v)
	}

	record.Add("origin_service", originService)

	return h.Handler.Handle(ctx, record)
}

func ParseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func New(level slog.Level) *slog.Logger {
	log := slog.New(&Handler{slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})})

	return log
}

func FromContext(ctx context.Context) *slog.Logger {
	log, ok := ctx.Value(entity.CtxKeyLogger{}).(*slog.Logger)
	if !ok {
		return slog.New(slog.NewJSONHandler(io.Discard, nil))
	}

	return log
}

func SetRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, reqID)
}

func SetUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

func SetCallerService(ctx context.Context, callerService string) context.Context {
	return context.WithValue(ctx, ctxKeyCallerService, callerService)
}

func SetMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, ctxKeyMethod, method)
}

func SetLogType(ctx context.Context, logType string) context.Context {
	return context.WithValue(ctx, ctxKeyLogType, logType)
}

func SetIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ctxKeyIP, ip)
}

func SetURL(ctx context.Context, url string) context.Context {
	return context.WithValue(ctx, ctxKeyURL, url)
}

func SetDeviceID(ctx context.Context, deviceID string) context.Context {
	return context.WithValue(ctx, ctxKeyDeviceID, deviceID)
}

func SetUserAgent(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, ctxKeyUserAgent, userAgent)
}
