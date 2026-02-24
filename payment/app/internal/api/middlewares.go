package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v4/request"

	"github.com/samandr77/microservices/payment/internal/entity"
	"github.com/samandr77/microservices/payment/pkg/logger"
)

var skipLogging = map[string]struct{}{
	"/api/health":  {},
	"/api/metrics": {},
}

//go:generate go run go.uber.org/mock/mockgen@latest -source=middlewares.go -destination=../mocks/middlewares.go -package=mocks -typed

type AuthService interface {
	User(ctx context.Context, token string) (entity.User, error)
}

type Middleware struct {
	auth          AuthService
	apiKeyEnabled bool
	apiKey        string
	vtbWL         []string
}

func NewMiddleware(auth AuthService, apiKeyEnabled bool, apiKey string, vtbWL []string) *Middleware {
	return &Middleware{
		auth:          auth,
		apiKeyEnabled: apiKeyEnabled,
		apiKey:        apiKey,
		vtbWL:         vtbWL,
	}
}

func (m *Middleware) Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = uuid.Must(uuid.NewV4()).String()
		}

		ctx = logger.WithRequestID(ctx, requestID)
		w.Header().Set("X-Request-Id", requestID)

		if _, ok := skipLogging[r.URL.Path]; !ok {
			reqBody, err := io.ReadAll(r.Body)
			if err != nil {
				SendJSONErr(ctx, w, http.StatusInternalServerError, err, "read request body")
				return
			}

			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(reqBody))

			var headers strings.Builder

			for k, v := range r.Header {
				if k == "Authorization" || k == "Cookie" {
					continue
				}

				headers.WriteString(fmt.Sprintf("%s: %s,\n", k, v))
			}

			slog.InfoContext(ctx, "incoming request",
				"request", fmt.Sprintf("%s %s\n%s", r.Method, r.URL.Redacted(), reqBody),
				"headers", headers.String(),
			)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		defer func() {
			err := recover()
			if err != nil {
				slog.ErrorContext(ctx, "recovered from panic", "error", err, "stack", string(debug.Stack()))
			}
		}()

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

// BearerAuth verifies incoming JWT using auth service.
func (m *Middleware) BearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token, err := request.BearerExtractor{}.ExtractToken(r)
		if err != nil {
			SendJSONErr(ctx, w, http.StatusUnauthorized, err, "Токен отсутствует или невалиден")
			return
		}

		user, err := m.auth.User(ctx, token)
		if err != nil {
			if errors.Is(err, entity.ErrForbidden) {
				SendJSONErr(ctx, w, http.StatusUnauthorized, err, "Неверный токен")
			} else {
				SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Ошибка аутентификации")
			}

			return
		}

		ctx = entity.CtxWithUser(ctx, user)
		ctx = logger.WithUserID(ctx, user.ID)
		ctx = entity.CtxWithJWT(ctx, token)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// APIKeyAuth verifies incoming API key.
func (m *Middleware) APIKeyAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if !m.apiKeyEnabled {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-Api-Key")
		if apiKey == "" {
			SendJSONErr(ctx, w, http.StatusUnauthorized, nil, "Отсутствует API ключ")
			return
		}

		if apiKey != m.apiKey {
			SendJSONErr(ctx, w, http.StatusUnauthorized, nil, "Неверный API ключ")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// VTBBankIPWL verifies incoming request IP against whitelist.
func (m *Middleware) VTBBankIPWL(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if len(m.vtbWL) != 0 {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				SendJSONErr(ctx, w, http.StatusUnauthorized, err, "ip check failed")
				return
			}

			if slices.Contains(m.vtbWL, host) {
				SendJSONErr(ctx, w, http.StatusForbidden, nil, "ip is not allowed")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
