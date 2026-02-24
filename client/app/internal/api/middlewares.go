package api

import (
	"context"
	"crypto/md5" //nolint:gosec // MD5 used for device fingerprinting, not cryptography
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v4/request"
	"github.com/samandr77/microservices/client/pkg/logger"

	"github.com/samandr77/microservices/client/internal/entity"
	"github.com/samandr77/microservices/client/pkg/config"
)

type AuthService interface {
	User(ctx context.Context, token string) (entity.User, error)
}

type PermissionService interface {
	ValidateUserPermission(ctx context.Context, userID uuid.UUID, permission string) error
}

type Middleware struct {
	auth    AuthService
	cfg     config.Config
	service PermissionService
}

func NewMiddleware(auth AuthService, cfg config.Config, service PermissionService) *Middleware {
	return &Middleware{
		auth:    auth,
		cfg:     cfg,
		service: service,
	}
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

		allowedHeaders := "Content-Type, Authorization, Origin, Accept, User-Agent, Cache-Control, X-Service-Name, X-User-ID"
		w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := logger.SetRequestID(r.Context(), uuid.Must(uuid.NewV4()).String())

		caller := r.Header.Get("X-Service-Name")
		if caller == "" {
			caller = "unknown"
		}

		ctx = logger.SetCallerService(ctx, caller)

		if ip, ok := ctx.Value(entity.CtxKeyIP{}).(string); ok && ip != "" {
			ctx = logger.SetIP(ctx, ip)
		}

		ctx = logger.SetURL(ctx, r.URL.String())
		ctx = logger.SetMethod(ctx, r.Method)
		ctx = logger.SetLogType(ctx, "webrequest")

		slog.InfoContext(ctx, "incoming request")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func(ctx context.Context) {
			err := recover()
			if err != nil {
				slog.ErrorContext(ctx, "panic", "error", err, "stack", string(debug.Stack()))
				w.WriteHeader(http.StatusInternalServerError)
			}
		}(r.Context())
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) WithIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ip string

		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ips := strings.Split(forwarded, ",")
			ip = strings.TrimSpace(ips[0])
		}

		if ip == "" {
			if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
				ip = strings.TrimSpace(realIP)
			}
		}

		if ip == "" {
			var err error

			ip, _, err = net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
		}

		ctx := context.WithValue(r.Context(), entity.CtxKeyIP{}, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func calculateDeviceID(userAgent, ip string) string {
	data := userAgent + ip
	hash := md5.Sum([]byte(data))

	return hex.EncodeToString(hash[:])
}

func (m *Middleware) WithDeviceID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		userAgent := r.Header.Get("User-Agent")
		ip, _ := ctx.Value(entity.CtxKeyIP{}).(string)
		deviceID := calculateDeviceID(userAgent, ip)

		ctx = logger.SetUserAgent(ctx, userAgent)
		ctx = logger.SetDeviceID(ctx, deviceID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		ctx = logger.SetLogType(ctx, "auth")

		token, err := request.BearerExtractor{}.ExtractToken(r)
		if err != nil {
			slog.WarnContext(ctx, "auth: bearer token extract failed")
			sendErr(ctx, w, http.StatusUnauthorized, err, entity.ErrMsgUnauthorized)

			return
		}

		user, err := m.auth.User(ctx, token)
		if err != nil {
			if errors.Is(err, entity.ErrUnauthorized) {
				slog.WarnContext(ctx, "auth: unauthorized from auth service")
				sendErr(ctx, w, http.StatusUnauthorized, err, entity.ErrMsgUnauthorized)
			} else {
				slog.ErrorContext(ctx, "auth: failed to validate token")
				sendErr(ctx, w, http.StatusInternalServerError, err, entity.ErrMsgInternal)
			}

			return
		}

		ctx = logger.SetUserID(ctx, user.UserID.String())
		ctx = entity.SetUserToContext(ctx, user)
		ctx = entity.SetTokenToContext(ctx, token)

		ctx = logger.SetLogType(ctx, "webrequest")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token, err := request.BearerExtractor{}.ExtractToken(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		user, err := m.auth.User(ctx, token)
		if err != nil {
			if errors.Is(err, entity.ErrUnauthorized) {
				sendErr(ctx, w, http.StatusUnauthorized, err, entity.ErrMsgUnauthorized)
			} else {
				sendErr(ctx, w, http.StatusInternalServerError, err, entity.ErrMsgInternal)
			}

			return
		}

		ctx = logger.SetUserID(ctx, user.UserID.String())
		ctx = entity.SetUserToContext(ctx, user)
		ctx = entity.SetTokenToContext(ctx, token)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Заменяет пробелы на '+' (которые могли появиться из-за URL декодирования).
func (m *Middleware) FixEmailParam(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if email := query.Get("email"); email != "" {
			originalEmail := email

			email = strings.ReplaceAll(email, " ", "+")
			email = strings.TrimSpace(email)

			if originalEmail != email {
				query.Set("email", email)
				r.URL.RawQuery = query.Encode()

				slog.DebugContext(r.Context(), "Email parameter normalized",
					"original", originalEmail,
					"normalized", email,
				)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) SecurityServiceAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token := r.Header.Get("X-Security-Token")
		if token == "" {
			slog.WarnContext(ctx, "security service auth: missing X-Security-Token header")
			sendErr(ctx, w, http.StatusUnauthorized, entity.ErrUnauthorized, "Missing security token")

			return
		}

		if m.cfg.SecurityServiceToken == "" {
			slog.ErrorContext(ctx, "security service auth: SECURITY_SERVICE_TOKEN not configured")
			sendErr(ctx, w, http.StatusInternalServerError, errors.New("security token not configured"), entity.ErrMsgInternal)

			return
		}

		if token != m.cfg.SecurityServiceToken {
			slog.WarnContext(ctx, "security service auth: invalid token")
			sendErr(ctx, w, http.StatusUnauthorized, entity.ErrUnauthorized, "Invalid security token")

			return
		}

		slog.DebugContext(ctx, "security service auth: token validated")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
