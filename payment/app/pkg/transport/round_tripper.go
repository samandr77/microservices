package transport

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/samandr77/microservices/payment/pkg/logger"
)

type JWTRoundTripper struct {
	Transport http.RoundTripper
}

func NewJWTRoundTripper(transport http.RoundTripper) *JWTRoundTripper {
	return &JWTRoundTripper{Transport: transport}
}

func (j *JWTRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()

	reqID := logger.RequestIDFromCtx(ctx)
	if reqID != "" {
		r.Header.Set("X-Request-Id", reqID)
	}

	// Log request
	slog.InfoContext(ctx, "outgoing request", "request", fmt.Sprintf("%s %s", r.Method, r.URL.Redacted()))

	// Perform request
	resp, err := j.Transport.RoundTrip(r)
	if err != nil {
		return nil, fmt.Errorf("round trip: %w", err)
	}

	slog.InfoContext(ctx, "incoming response", "response", fmt.Sprintf("%s %s", r.Method, r.URL.Redacted()))

	return resp, nil
}
