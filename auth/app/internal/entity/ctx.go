package entity

import (
	"context"
	"io"
	"log/slog"
)

type (
	CtxKeyLogger    struct{}
	CtxKeyIP        struct{}
	CtxKeyUserID    struct{}
	CtxKeyDeviceID  struct{}
	CtxKeyUserAgent struct{}
	CtxKeyLogType   struct{}
	CtxKeyMethod    struct{}
	CtxKeyURL       struct{}
)

func IPFromCtx(ctx context.Context) string {
	ip, ok := ctx.Value(CtxKeyIP{}).(string)
	if !ok {
		return ""
	}

	return ip
}

func LoggerFromContext(ctx context.Context) *slog.Logger {
	log, ok := ctx.Value(CtxKeyLogger{}).(*slog.Logger)
	if !ok {
		return slog.New(slog.NewJSONHandler(io.Discard, nil))
	}

	return log
}

func DeviceIDFromCtx(ctx context.Context) string {
	deviceID, ok := ctx.Value(CtxKeyDeviceID{}).(string)
	if !ok {
		return ""
	}

	return deviceID
}

func UserAgentFromCtx(ctx context.Context) string {
	ua, ok := ctx.Value(CtxKeyUserAgent{}).(string)
	if !ok {
		return ""
	}

	return ua
}

func LogTypeFromCtx(ctx context.Context) string {
	logType, ok := ctx.Value(CtxKeyLogType{}).(string)
	if !ok {
		return ""
	}

	return logType
}

func MethodFromCtx(ctx context.Context) string {
	method, ok := ctx.Value(CtxKeyMethod{}).(string)
	if !ok {
		return ""
	}

	return method
}

func URLFromCtx(ctx context.Context) string {
	url, ok := ctx.Value(CtxKeyURL{}).(string)
	if !ok {
		return ""
	}

	return url
}
