package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger"
	_ "github.com/samandr77/microservices/documents/docs" //nolint:revive,nolintlint
)

func NewRouter(h *Handler, mw *Middleware) http.Handler {
	router := chi.NewRouter()

	router.Use(mw.Log, mw.Recover, mw.Cors, mw.WithIP)

	router.Route("/api", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Get("/health", h.Health)
			r.Get("/swagger/*", httpSwagger.WrapHandler)
		})

		r.Group(func(r chi.Router) {
			r.Use(mw.Auth)

			r.Post("/oferta", h.CreateOferta)
			r.Put("/oferta/sign", h.SignOferta)

			r.Post("/getDocuments", h.CreatClosingDocuments)

			r.Get("/documents", h.DocumentsByClientID)
			r.Get("/documents/list", h.GetDocumentsList)
			r.Get("/documents/details", h.GetDocumentDetails)
			r.Get("/documents/download", h.DownloadDocument)
		})

		r.Post("/private/act/callback", h.ClosingDocuments)
	})

	return router
}
