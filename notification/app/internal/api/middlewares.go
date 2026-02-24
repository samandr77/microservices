package api

import (
	"context"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gofrs/uuid/v5"
	"github.com/samandr77/microservices/notification/internal/entity"
)

type Middleware struct {
	log *slog.Logger
}

func NewMiddleware(log *slog.Logger) *Middleware {
	return &Middleware{
		log: log,
	}
}

func (m *Middleware) Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := m.log.With("request_id", uuid.Must(uuid.NewV4()))

		l.Info("incoming request", "method", r.Method, "url", r.URL.String(), "from", r.RemoteAddr)

		ctx := context.WithValue(r.Context(), entity.CtxKeyLogger{}, l)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			err := recover()
			if err != nil {
				m.log.Error("panic", "error", err, "stack", string(debug.Stack()))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
