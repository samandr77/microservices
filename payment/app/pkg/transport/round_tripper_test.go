package transport_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/samandr77/microservices/payment/pkg/transport"
)

//nolint:paralleltest
func TestRoundTripper_RoundTrip(t *testing.T) {
	buf := new(bytes.Buffer)

	now := time.Now().Format(time.DateOnly)

	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == "time" {
				return slog.Attr{Key: a.Key, Value: slog.StringValue(now)}
			}
			return a
		},
	})))

	mux := http.DefaultServeMux
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"message": "hello world"}`)
	})
	mux.HandleFunc("/test2", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `[{"message": "hello world"}]`)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := &http.Client{
		Timeout:   time.Second * 10,
		Transport: transport.NewJWTRoundTripper(http.DefaultTransport),
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost, server.URL+"/test",
		strings.NewReader(`{"data": "hi server"}`),
	)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	req, err = http.NewRequestWithContext(
		context.Background(),
		http.MethodPost, server.URL+"/test2",
		strings.NewReader(`[{"data": "hi server"}]`),
	)
	require.NoError(t, err)

	resp2, err := client.Do(req)
	require.NoError(t, err)

	defer resp2.Body.Close()

	require.Equal(t, buf.String(),
		fmt.Sprintf(`{"time":"%s","level":"INFO","msg":"outgoing request","request":"POST %s/test"}
{"time":"%s","level":"INFO","msg":"incoming response","response":"POST %s/test"}
{"time":"%s","level":"INFO","msg":"outgoing request","request":"POST %s/test2"}
{"time":"%s","level":"INFO","msg":"incoming response","response":"POST %s/test2"}
`, now, server.URL, now, server.URL, now, server.URL, now, server.URL))
}
