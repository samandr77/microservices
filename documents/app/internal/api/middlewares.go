package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5/request"
	"github.com/samandr77/microservices/documents/internal/entity"
	"github.com/samandr77/microservices/documents/pkg/config"
	"github.com/samandr77/microservices/documents/pkg/logger"
)

type Middleware struct {
	cfg config.Config
}

func NewMiddleware(cfg config.Config) *Middleware {
	return &Middleware{
		cfg: cfg,
	}
}

func (m *Middleware) Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := logger.SetRequestID(r.Context(), uuid.Must(uuid.NewV4()).String())

		headers := ""

		for k, v := range r.Header {
			if k == "Authorization" {
				continue
			}

			headers += fmt.Sprintf("%s: %s,\n", k, v)
		}

		slog.InfoContext(ctx, "incoming request", "method", r.Method, "url", r.URL.String(), "headers", headers, "user_ip", r.RemoteAddr)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func(ctx context.Context) {
			err := recover()
			if err != nil {
				slog.ErrorContext(ctx, "panic", "error", err, "stack", string(debug.Stack()))
			}
		}(r.Context())
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) Cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Origin, Accept, User-Agent, Cache-Control")

		if r.Method == http.MethodOptions {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) WithIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), entity.CtxKeyIP{}, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (m *Middleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ctx        = r.Context()
			user       entity.User
			httpClient = &http.Client{}
		)

		accessToken, err := request.BearerExtractor{}.ExtractToken(r)
		if err != nil {
			SendErr(ctx, w, http.StatusUnauthorized, err, "Нет токена в заголовке")
			return
		}

		data := map[string]string{
			"accessToken": accessToken,
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			SendErr(ctx, w, http.StatusInternalServerError, err, errInternalRuText)
			return
		}

		req, err := http.NewRequestWithContext(r.Context(),
			http.MethodPost, fmt.Sprintf("%s/api/validate", m.cfg.AuthServiceURL), bytes.NewReader(jsonData)) //nolint:perfsprint
		if err != nil {
			SendErr(ctx, w, http.StatusInternalServerError, err, errInternalRuText)
			return
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			SendErr(ctx, w, http.StatusInternalServerError, err, errInternalRuText)
			return
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			SendErr(ctx, w, http.StatusUnauthorized, fmt.Errorf("unexpected status code %d", resp.StatusCode), errInternalRuText)
			return
		}

		err = json.NewDecoder(resp.Body).Decode(&user)
		if err != nil {
			SendErr(ctx, w, http.StatusInternalServerError, err, errInternalRuText)
			return
		}

		ctx = logger.SetUserID(ctx, user.ID.String())
		ctx = entity.SetUserToContext(ctx, user)
		ctx = entity.SetTokenToContext(ctx, accessToken)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
