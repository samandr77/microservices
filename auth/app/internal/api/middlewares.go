package api

import (
	"context"
	"crypto/md5" //nolint:gosec // G501: MD5 used for non-cryptographic device fingerprinting
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/samandr77/microservices/auth/pkg/logger"

	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/internal/service"
)

type Middleware struct {
	s *service.Service
}

func NewMiddleware(s *service.Service) *Middleware {
	return &Middleware{
		s: s,
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Origin, Accept, User-Agent, Cache-Control, X-Service-Name")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) Log(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		ctx := logger.SetRequestID(r.Context(), uuid.Must(uuid.NewV4()).String())

		ctx = logger.SetMethod(ctx, r.Method)
		ctx = logger.SetURL(ctx, r.URL.Path)
		ctx = logger.SetUserAgent(ctx, r.UserAgent())
		ctx = logger.SetLogType(ctx, "webrequest")

		callerService := r.Header.Get("X-Service-Name")
		if callerService == "" {
			callerService = "unknown"
		}

		ctx = logger.SetCallerService(ctx, callerService)

		ip := entity.IPFromCtx(ctx)
		ctx = logger.SetIP(ctx, ip)

		deviceID := entity.DeviceIDFromCtx(ctx)
		ctx = logger.SetDeviceID(ctx, deviceID)

		slog.InfoContext(ctx, "incoming request")

		next.ServeHTTP(w, r.WithContext(ctx))

		duration := time.Since(start)
		slog.InfoContext(ctx, "request completed", "duration_ms", duration.Milliseconds())
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

func (m *Middleware) WithIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := removePort(r.RemoteAddr)

		if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
			parts := splitAndTrim(xForwardedFor, ",")

			for _, part := range parts {
				part = removePort(part)
				if isValidIP(part) {
					ip = part
					break
				}
			}
		}

		if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
			xRealIP = removePort(xRealIP)
			if isValidIP(xRealIP) {
				ip = xRealIP
			}
		}

		if !isValidIP(ip) {
			slog.Warn("invalid IP detected, using fallback", "ip", ip, "remote_addr", r.RemoteAddr)
			ip = "unknown"
		}

		ctx := context.WithValue(r.Context(), entity.CtxKeyIP{}, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) WithDeviceID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		ip := entity.IPFromCtx(ctx)
		userAgent := r.UserAgent()

		deviceID := hashDeviceID(ip, userAgent)

		ctx = context.WithValue(ctx, entity.CtxKeyDeviceID{}, deviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func removePort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}

	return host
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := []string{}

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)

	return parsedIP != nil
}
func hashDeviceID(ip, userAgent string) string {
	if ip == "" && userAgent == "" {
		return ""
	}

	data := fmt.Sprintf("%s|%s", ip, userAgent)
	hash := md5.Sum([]byte(data))

	return hex.EncodeToString(hash[:])
}
