package api

import (
	"net/http"

	httpSwagger "github.com/swaggo/http-swagger"

	// swagger docs
	_ "github.com/samandr77/microservices/client/docs"
)

func NewRouter(h *Handler, mw *Middleware) http.Handler {
	router := http.NewServeMux()

	// Public routes (без авторизации)
	router.HandleFunc("/api/health", h.Health)
	router.HandleFunc("/api/swagger/", httpSwagger.WrapHandler)

	// Internal routes (без авторизации, межсервисное взаимодействие)
	router.HandleFunc("POST /internal/users/create", h.CreateUser)
	router.HandleFunc("PUT /internal/users/update", h.UpdateUserInternal)
	router.Handle("GET /internal/users", use(http.HandlerFunc(h.SearchUser), mw.FixEmailParam))
	router.HandleFunc("GET /internal/users/{user_id}", h.GetUser)
	router.HandleFunc("POST /internal/users/temporary-block", h.BlockUserInternal)
	router.HandleFunc("POST /internal/users/restore", h.RestoreUser)

	// Protected routes (с авторизацией, пользовательские методы)
	router.Handle("GET /users/me", use(http.HandlerFunc(h.GetUserMe), mw.Auth))
	router.Handle("PUT /users/update", use(http.HandlerFunc(h.UpdateUser), mw.Auth))
	router.Handle("DELETE /users/me", use(http.HandlerFunc(h.DeleteUser), mw.Auth))

	// Security service routes (с токеном службы безопасности)
	router.Handle("POST /users/block", use(http.HandlerFunc(h.BlockUser), mw.SecurityServiceAuth))
	router.Handle("POST /users/unblock", use(http.HandlerFunc(h.UnblockUser), mw.SecurityServiceAuth))

	handler := use(router, mw.Recover, mw.Cors, mw.WithIP, mw.WithDeviceID, mw.Log)

	return handler
}

func use(handler http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}

	return handler
}
