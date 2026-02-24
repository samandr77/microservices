package logger

import (
	"log/slog"
	"os"
)

func New(level slog.Level) *slog.Logger {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	return log
}
