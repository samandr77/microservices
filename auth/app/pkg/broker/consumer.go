package broker

import (
	"fmt"
	"log/slog"
)

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
