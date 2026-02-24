package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	httpSwagger "github.com/swaggo/http-swagger/v2"

	_ "github.com/samandr77/microservices/payment/docs" // swagger docs
)

func NewRouter(h *Handler, mw *Middleware) http.Handler {
	mux := chi.NewRouter()
	mux.Use(mw.Log, mw.Recover, mw.Cors)

	mux.Route("/api", func(r chi.Router) {
		r.HandleFunc("/health", h.HealthHandler)
		r.HandleFunc("/swagger/*", httpSwagger.Handler())

		r.Route("/payments", func(r chi.Router) {
			r.Use(mw.BearerAuth)
			r.Get("/transactions/{client_id}", h.Transactions)
			r.Get("/invoices/{txId}", h.InvoiceURL)
			r.Post("/invoices", h.CreateInvoice)
			r.Post("/spb", h.CreateSPBLink)
			r.Post("/card", h.CreateCardPayment)
		})

		r.Route("/payments/callbacks", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Get("/card", h.CardPaymentCallback)
			})

			r.Group(func(r chi.Router) {
				r.Use(mw.VTBBankIPWL)
				r.Post("/sbp", h.SBPCallback)
			})
		})

		r.Route("/private/v1/onec", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(mw.APIKeyAuth)
				r.Post("/invoice", h.InvoiceCallback)
				r.Post("/invoice/file", h.SaveInvoiceURL)
			})
		})

		r.Route("/internal", func(r chi.Router) {
			r.Use(mw.BearerAuth)
			r.Post("/debits", h.CreateDebit)
		})
	})

	return mux
}
