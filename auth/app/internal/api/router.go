package api

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger"
	_ "github.com/samandr77/microservices/auth/docs" // Для генерации Swagger-документации
)

func NewRouter(h *Handler, mw *Middleware) http.Handler {
	router := http.NewServeMux()

	router.HandleFunc("/api/health", h.Health)

	router.HandleFunc("POST /api/code/send", h.SendCode)
	router.HandleFunc("POST /api/code/check", h.CheckCode)
	router.HandleFunc("POST /api/token/validate", h.ValidateToken)
	router.HandleFunc("POST /api/token/destroy", h.DestroyToken)
	router.HandleFunc("POST /api/token/refresh", h.RefreshToken)
	router.HandleFunc("POST /api/openid/code", h.RegisterWithSberID)
	router.HandleFunc("GET /api/sberid/config", h.GetSberIDConfig)
	router.HandleFunc("POST /api/email/update", h.UpdateEmailSelection)

	router.HandleFunc("POST /internal/api/token/destroy", h.DestroyTokenInternal)

	router.HandleFunc("/api/swagger/", httpSwagger.WrapHandler)

	handler := use(router, mw.Recover, mw.Cors, mw.WithIP, mw.WithDeviceID, mw.Log)

	return handler
}

func use(handler http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}

	return handler
}
