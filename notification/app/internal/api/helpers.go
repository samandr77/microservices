package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/samandr77/microservices/notification/internal/entity"
)

type ResponseError struct {
	Message string `json:"message"`
}

func SendErr(ctx context.Context, w http.ResponseWriter, code int, err error, msg string) {
	l, ok := ctx.Value(entity.CtxKeyLogger{}).(*slog.Logger)
	if ok {
		l.Error("api error", "error", err, "code", code)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	err = json.NewEncoder(w).Encode(ResponseError{Message: msg})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func SendJSON(ctx context.Context, w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		SendErr(ctx, w, http.StatusInternalServerError, err, "")
		return
	}
}
