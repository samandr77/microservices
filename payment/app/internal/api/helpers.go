package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

type ErrorResponse struct {
	Message     string `json:"message"`
	Description string `json:"description,omitempty"`
}

func SendJSONErr(ctx context.Context, w http.ResponseWriter, code int, originErr error, msgToSend string) {
	slog.ErrorContext(ctx, "api error", "error", originErr.Error())
	SendJSON(ctx, w, code, ErrorResponse{Message: msgToSend, Description: originErr.Error()})
}

func SendJSON(ctx context.Context, w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		code = http.StatusInternalServerError
		http.Error(w, http.StatusText(code), code)

		slog.ErrorContext(ctx, "encode response", "error", err)
	}
}
