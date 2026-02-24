package api

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger"
	_ "github.com/samandr77/microservices/notification/docs" //nolint:revieve
)

func NewRouter(h *Handler, mw *Middleware) http.Handler {
	router := http.NewServeMux()

	router.HandleFunc("/api/health", h.Health)
	router.HandleFunc("/api/swagger/", httpSwagger.WrapHandler)
	router.HandleFunc("POST /api/messages", h.SendMessage)

	return mw.Recover(mw.Log(router))
}
