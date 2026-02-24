package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

const errInternalRuText = "Внутренняя ошибка"

type ResponseError struct {
	Message string `json:"message"`
	Error   string `json:"error"`
}

func SendErr(ctx context.Context, w http.ResponseWriter, code int, err error, msg string) {
	slog.ErrorContext(ctx, "api error", "error", err, "code", code)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	err = json.NewEncoder(w).Encode(ResponseError{Message: msg, Error: err.Error()})
	if err != nil {
		slog.ErrorContext(ctx, "api error", "error", err, "code", http.StatusInternalServerError)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
