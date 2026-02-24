package api

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"

	"github.com/samandr77/microservices/payment/internal/entity"
)

// @title Payment API
// @version 1.0
// @description This is an API for user payments to increase their balance
// @BasePath /payment/api
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-Api-Key

var MinimalPaymentAmount = decimal.RequireFromString("1000.00")

type Service interface {
	CreateInvoice(ctx context.Context, amount decimal.Decimal) (entity.Invoice, error)
	CreateSPBLink(ctx context.Context, amount decimal.Decimal) (entity.SPBLink, error)
	InvoicePaid(ctx context.Context, req entity.InvoiceCallback) error
	SBPPaid(ctx context.Context, tx uuid.UUID) error
	Transactions(ctx context.Context, clientID uuid.UUID, filter entity.TransactionFilter) ([]entity.Transaction, int, error)
	CreateDebit(ctx context.Context, clientID uuid.UUID, userID uuid.UUID, campaignName string, amount decimal.Decimal) error
	CreateCardPayment(ctx context.Context, amount decimal.Decimal) (entity.CardPayment, error)
	CardPaymentPaid(ctx context.Context, tx uuid.UUID) error
	SaveInvoiceURL(ctx context.Context, billNumber int64, url string) error
	Transaction(ctx context.Context, id uuid.UUID) (entity.Transaction, error)
}

type Handler struct {
	s                        Service
	cardCallbackCheckEnabled bool
	cardCallbackPublicKey    *rsa.PublicKey
}

func NewHandler(s Service, cardCallbackCheckEnabled bool, cardCallbackPublicKey *rsa.PublicKey) *Handler {
	return &Handler{
		s:                        s,
		cardCallbackCheckEnabled: cardCallbackCheckEnabled,
		cardCallbackPublicKey:    cardCallbackPublicKey,
	}
}

type CreateInvoiceRequest struct {
	Amount decimal.Decimal `json:"amount"`
}

type CreateInvoiceResponse struct {
	TxID              uuid.UUID               `json:"txId"`
	PayerType         string                  `json:"payerType"`
	Service           string                  `json:"service"`
	Amount            string                  `json:"amount"`
	ClientName        string                  `json:"clientName"`
	ClientINN         string                  `json:"clientINN"`
	ClientOGRN        string                  `json:"clientOGRN"`
	ClientAddress     string                  `json:"clientAddress"`
	ClientMailAddress string                  `json:"clientMailAddress"`
	ClientMailIndex   string                  `json:"clientMailIndex"`
	Requisites        entity.ClientRequisites `json:"requisites"`
	ClientKPP         string                  `json:"clientKPP"`
	Number            int64                   `json:"number"`
}

// CreateInvoice creates an invoice for the specified amount
// @Summary Create invoice
// @Description Creates a bill invoice to increase user balance
// @Tags payments
// @Accept json
// @Produce json
// @Param CreateInvoiceRequest body CreateInvoiceRequest true "Invoice creation request"
// @Success 201 {object} CreateInvoiceResponse
// @Failure 400 {object} ErrorResponse "Client not approved"
// @Failure 403 {object} ErrorResponse "Action forbidden for user"
// @Failure 422 {object} ErrorResponse "Amount must be positive"
// @Failure 404 {object} ErrorResponse "Client not found"
// @Failure 500 {object} ErrorResponse "Failed to create invoice"
// @Router /payments/invoices [post]
// @Security BearerAuth
func (h *Handler) CreateInvoice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateInvoiceRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, "Невалидный JSON")
		return
	}

	if req.Amount.LessThan(MinimalPaymentAmount) {
		SendJSONErr(ctx, w, http.StatusUnprocessableEntity,
			fmt.Errorf("not positive amount %s", req.Amount), "Сумма должна быть не менее 1000 рублей")
		return
	}

	invoice, err := h.s.CreateInvoice(ctx, req.Amount)
	if err != nil {
		switch {
		case errors.Is(err, entity.ErrNotFound):
			SendJSONErr(ctx, w, http.StatusNotFound, err, "Клиент не найден")
		case errors.Is(err, entity.ErrForbidden):
			SendJSONErr(ctx, w, http.StatusForbidden, err, "Не хватает прав для выполнения действия")
		case errors.Is(err, entity.ErrClientNotApproved):
			SendJSONErr(ctx, w, http.StatusBadRequest, err, "Клиент не подтвержден")
		case errors.Is(err, entity.ErrInvalidOfertaStatus):
			SendJSONErr(ctx, w, http.StatusBadRequest, err, "Неверный статус оферты")
		default:
			SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Не удалось создать счет")
		}

		return
	}

	SendJSON(ctx, w, http.StatusCreated, CreateInvoiceResponse{
		TxID:              invoice.TxID,
		Number:            invoice.Number,
		PayerType:         invoice.PayerType,
		Service:           invoice.Service,
		Amount:            invoice.Amount.String(),
		ClientName:        invoice.Client.Name,
		ClientINN:         invoice.Client.INN,
		ClientOGRN:        invoice.Client.OGRN,
		ClientKPP:         invoice.Client.KPP,
		ClientAddress:     invoice.Client.Address.String(),
		ClientMailAddress: invoice.Client.Address.String(),
		ClientMailIndex:   invoice.Client.Address.Index,
		Requisites:        invoice.Requisites,
	})
}

type InvoiceCallbackRequest struct {
	GUID          uuid.UUID       `json:"guid"`
	BillNumber    decimal.Decimal `json:"billNumber"`
	BillDate      time.Time       `json:"billDate"`
	TotalAmount   decimal.Decimal `json:"totalAmount"`
	InvoiceID     uuid.UUID       `json:"invoiceId"`
	OperationID   uuid.UUID       `json:"operationId"`
	OperationDate time.Time       `json:"operationDate"`
	Sender        struct {
		Name string `json:"name"`
		Inn  string `json:"inn"`
		Bank string `json:"bank"`
	} `json:"sender"`
}

type InvoiceCallbackResponse struct {
}

// InvoiceCallback updates the invoice status
// @Summary Update invoice
// @Description Callback to update the invoice status after payment
// @Tags payments
// @Accept json
// @Produce json
// @Param InvoiceCallbackRequest body InvoiceCallbackRequest true "Invoice callback request"
// @Success 200 {object} InvoiceCallbackResponse
// @Failure 400 {object} ErrorResponse "Invalid GUID or invalid input data"
// @Failure 404 {object} ErrorResponse "Invoice not found"
// @Failure 500 {object} ErrorResponse "Failed to update invoice"
// @Router /private/v1/onec/invoice [post]
// @Security APIKeyAuth
func (h *Handler) InvoiceCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req InvoiceCallbackRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, "Невалидный JSON")
		return
	}

	ic := entity.InvoiceCallback{
		GUID:        req.GUID,
		BillNumber:  req.BillNumber.IntPart(),
		BillDate:    req.BillDate,
		TotalAmount: req.TotalAmount,
	}

	err = h.s.InvoicePaid(ctx, ic)

	switch {
	case err == nil:
		SendJSON(ctx, w, http.StatusOK, InvoiceCallbackResponse{})
	case errors.Is(err, entity.ErrNotFound):
		SendJSONErr(ctx, w, http.StatusNotFound, err, "Счет не найден")
	case errors.Is(err, entity.ErrAlreadyPaid):
		SendJSON(ctx, w, http.StatusOK, InvoiceCallbackResponse{})
	default:
		SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Не удалось обновить счет")
	}
}

type CreateSPBLinkRequest struct {
	Amount decimal.Decimal `json:"amount"`
}

type CreateSPBLinkResponse struct {
	Data entity.SPBLink `json:"data"`
}

// CreateSPBLink creates a link to pay through SPB
// @summary Создать ссылку на оплату через СПБ
// @tags payments
// @accept application/json
// @produce application/json
// @param CreateSPBLinkRequest body CreateSPBLinkRequest true "Запрос на создание СПБ-ссылки"
// @success 200 {object} CreateSPBLinkResponse "Ссылка успешно создана"
// @failure 400 {object} ErrorResponse "Невалидное тело запроса"
// @failure 422 {object} ErrorResponse "Сумма должна быть положительной"
// @failure 500 {object} ErrorResponse "Не удалось создать СПБ-ссылку"
// @router /payments/spb [post]
// @security BearerAuth
func (h *Handler) CreateSPBLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateSPBLinkRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendJSONErr(r.Context(), w, http.StatusBadRequest, err, err.Error())
		return
	}

	if req.Amount.LessThan(MinimalPaymentAmount) {
		SendJSONErr(ctx, w, http.StatusUnprocessableEntity,
			fmt.Errorf("not positive amount %s", req.Amount), "Сумма должна быть не менее 1000 рублей")
		return
	}

	spbLink, err := h.s.CreateSPBLink(ctx, req.Amount)
	if err != nil {
		SendJSONErr(r.Context(), w, http.StatusInternalServerError, err, "failed to create spb link")
		return
	}

	SendJSON(ctx, w, http.StatusOK, CreateSPBLinkResponse{Data: spbLink})
}

type SBPCallbackRequest struct {
	AnID           string    `json:"anId"`
	QrcID          string    `json:"qrcId"`
	TrxID          string    `json:"trxId"`
	Status         string    `json:"status"`
	OrderID        string    `json:"orderId"`
	RequestID      uuid.UUID `json:"requestId"`
	Amount         string    `json:"amount"`    // Units
	TaxAmount      string    `json:"TaxAmount"` // Units
	PaymentPurpose string    `json:"paymentPurpose"`
	Timestamp      time.Time `json:"timestamp"`
	SenderName     string    `json:"senderName"`
	SenderInn      string    `json:"senderInn"`
	SenderBank     string    `json:"senderBank"`
}

type SBPCallbackResponse struct{}

// SBPCallback updates the invoice status
// @Summary Handle SPB callback
// @Description Callback to update the SPB payment status after payment
// @Tags payments
// @Accept json
// @Produce json
// @Param SBPCallbackRequest body SBPCallbackRequest true "Invoice callback request"
// @Success 200 {object} SBPCallbackResponse
// @Failure 400 {object} ErrorResponse "invalid json"
// @Failure 404 {object} ErrorResponse "payment not found"
// @Failure 500 {object} ErrorResponse "internal server error"
// @Router /payments/callbacks/sbp [post]
func (h *Handler) SBPCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SBPCallbackRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, err.Error())
		return
	}

	if req.Status != entity.SPBPaymentStatusPaid.String() {
		slog.WarnContext(ctx, fmt.Sprintf("go spb payment status %q is not %q : ", req.Status, entity.SPBPaymentStatusPaid))
		SendJSON(ctx, w, http.StatusOK, SBPCallbackResponse{})
		return
	}

	err = h.s.SBPPaid(ctx, req.RequestID)

	switch {
	case err == nil:
		SendJSON(ctx, w, http.StatusOK, SBPCallbackResponse{})
	case errors.Is(err, entity.ErrNotFound):
		SendJSONErr(ctx, w, http.StatusNotFound, err, "SPB payment not found")
	case errors.Is(err, entity.ErrAlreadyPaid):
		SendJSON(ctx, w, http.StatusOK, SBPCallbackResponse{})
	default:
		SendJSONErr(ctx, w, http.StatusInternalServerError, err, "failed to update SPB payment")
	}
}

type TransactionsResponse struct {
	Transactions []TransactionEntity `json:"transactions"`
	TotalCount   int                 `json:"totalCount"`
}

type TransactionEntity struct {
	ID            string    `json:"id"`
	Amount        string    `json:"amount"`
	Name          string    `json:"name"`
	Number        int64     `json:"number"`
	ClientID      string    `json:"clientID"`
	ClientGUID    string    `json:"clientGUID"`
	PaymentMethod string    `json:"paymentMethod"`
	Status        string    `json:"status"`
	InvoiceURL    string    `json:"invoiceURL"`
	CreatedBy     string    `json:"createdBy"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// Transactions retrieves transaction history for a client with optional filters
// @Summary Получение истории транзакций клиента
// @Description Позволяет получить список транзакций для клиента по его уникальному идентификатору с поддержкой фильтрации, сортировки и пагинации
// @Tags payments
// @Accept json
// @Produce json
// @Param client_id path string true "Идентификатор клиента"
// @Param id query string false "Фильтр по идентификатору транзакции"
// @Param amount query string false "Фильтр по сумме транзакции"
// @Param createdAt query string false "Фильтр по дате создания транзакции (формат: YYYY-MM-DD)"
// @Param limit query int false "Лимит количества транзакций на странице (по умолчанию 10)"
// @Param page query int false "Номер страницы для пагинации (по умолчанию 1)"
// @Param sortBy query string false "Поле для сортировки (доступны: id, amount, createdAt)"
// @Param orderBy query string false "Порядок сортировки (asc для возрастания, desc для убывания)"
// @Success 200 {object} TransactionsResponse "История транзакций клиента"
// @Failure 400 {object} ErrorResponse "Невалидное тело запроса"
// @Failure 403 {object} ErrorResponse "Доступ запрещен"
// @Failure 500 {object} ErrorResponse "Не удалось получить историю транзакций"
// @Router /payments/transactions/{client_id} [get]
func (h *Handler) Transactions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sClientID := chi.URLParam(r, "client_id")
	if sClientID == "" {
		SendJSONErr(ctx, w, http.StatusBadRequest, nil, "client_id is required")
		return
	}

	clientID, err := uuid.FromString(sClientID)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, "invalid client_id")
		return
	}

	filter := parseTransactionFilter(r.URL.Query())

	transactions, totalCount, err := h.s.Transactions(ctx, clientID, filter)
	if err != nil {
		if errors.Is(err, entity.ErrForbidden) {
			SendJSONErr(ctx, w, http.StatusForbidden, err, "forbidden")
			return
		}

		SendJSONErr(ctx, w, http.StatusInternalServerError, err, "failed to get transactions")

		return
	}

	SendJSON(ctx, w, http.StatusOK, TransactionsResponse{Transactions: transactionsToAPI(transactions),
		TotalCount: totalCount})
}

func parseTransactionFilter(url url.Values) entity.TransactionFilter {
	const (
		defaultLimit uint64 = 10
		maxLimit     uint64 = 100
		defaultPage  uint64 = 1
	)

	id := url.Get("id")
	amount := url.Get("amount")
	createdAt := url.Get("createdAt")
	qLimit := url.Get("limit")
	qPage := url.Get("page")
	sortBy := entity.TransactionSortCol(url.Get("sortBy"))
	orderBy := entity.OrderByCol(url.Get("orderBy"))

	limit, err := strconv.ParseUint(qLimit, 10, 64)
	if err != nil {
		limit = defaultLimit
	}

	if limit > maxLimit {
		limit = maxLimit
	}

	page, err := strconv.ParseUint(qPage, 10, 64)
	if err != nil {
		page = defaultPage
	}

	if !sortBy.IsValid() {
		sortBy = entity.SortByCreatedAt
	}

	if !orderBy.IsValid() {
		orderBy = entity.DESC
	}

	filter := entity.TransactionFilter{
		Page:    page,
		Limit:   limit,
		SortBy:  sortBy,
		OrderBy: orderBy,
	}

	if id != "" {
		filter.ID = &id
	}

	if amount != "" {
		filter.Amount = &amount
	}

	if createdAt != "" {
		filter.CreatedAt = &createdAt
	}

	return filter
}

func transactionsToAPI(transactions []entity.Transaction) []TransactionEntity {
	res := make([]TransactionEntity, 0, len(transactions))
	for _, t := range transactions {
		res = append(res, TransactionEntity{
			ID:            t.ID.String(),
			Amount:        t.Amount.String(),
			Name:          t.Name,
			Number:        t.Number,
			ClientID:      t.ClientID.String(),
			ClientGUID:    t.ClientGUID.String(),
			PaymentMethod: t.PaymentMethod.String(),
			Status:        t.Status.String(),
			InvoiceURL:    t.InvoiceURL,
			CreatedBy:     t.CreatedBy.String(),
			CreatedAt:     t.CreatedAt,
			UpdatedAt:     t.UpdatedAt,
		})
	}

	return res
}

// HealthHandler - returns service health status.
// @Summary Health check
// @Description Health check
// @Tags health
// @Accept text/plain
// @Produce text/plain
// @Success 200 {string} string "Сервис работает!"
// @Router /health [get]
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := w.Write([]byte("Сервис работает!\n"))
	if err != nil {
		SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Сервис не работает!")
		return
	}
}

type CreateDebitRequest struct {
	ClientID     uuid.UUID       `json:"clientID"`
	UserID       uuid.UUID       `json:"userID"`
	CampaignName string          `json:"campaignName"`
	Amount       decimal.Decimal `json:"amount"`
}

type CreateDebitResponse struct {
}

func (h *Handler) CreateDebit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateDebitRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, "Невалидный JSON")
		return
	}

	if !req.Amount.IsNegative() {
		SendJSONErr(ctx, w, http.StatusUnprocessableEntity, fmt.Errorf("not positive amount %s", req.Amount), "Сумма должна быть меньше нуля")
		return
	}

	err = h.s.CreateDebit(ctx, req.ClientID, req.UserID, req.CampaignName, req.Amount)
	if err != nil {
		if errors.Is(err, entity.ErrForbidden) {
			SendJSONErr(ctx, w, http.StatusForbidden, err, "недостаточно прав")
			return
		}

		SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Не удалось создать дебет")

		return
	}

	SendJSON(ctx, w, http.StatusOK, CreateDebitResponse{})
}

type SaveInvoiceURLRequest struct {
	GUID       uuid.UUID       `json:"guid"`
	BillNumber decimal.Decimal `json:"billNumber"`
	BillDate   time.Time       `json:"billDate"`
	URL        string          `json:"url"`
}

type SaveInvoiceURLResponse struct {
}

// SaveInvoiceURL сохраняет URL счета по номеру счета и GUID
// @Summary Save invoice URL
// @Description Saves the invoice URL with the specified bill number and GUID
// @Tags invoices
// @Accept json
// @Produce json
// @Param request body SaveInvoiceURLRequest true "Invoice URL save request"
// @Success 200 {object} SaveInvoiceURLResponse
// @Failure 400 {object} ErrorResponse "Невалидное тело запроса"
// @Failure 500 {object} ErrorResponse "Не удалось сохранить ссылку"
// @Router /private/v1/onec/invoice/file [post]
func (h *Handler) SaveInvoiceURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SaveInvoiceURLRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, "Невалидный JSON")
		return
	}

	err = h.s.SaveInvoiceURL(ctx, req.BillNumber.IntPart(), req.URL)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Не удалось сохранить ссылку")
		return
	}

	SendJSON(ctx, w, http.StatusOK, SaveInvoiceURLResponse{})
}

type CreateCardPaymentRequest struct {
	Amount decimal.Decimal `json:"amount"`
}

type CreateCardPaymentResponse struct {
	Payment entity.CardPayment `json:"payment"`
}

// CreateCardPayment creates a card payment for the specified amount
// @Summary Create card payment
// @Description Creates a card payment for the specified amount
// @Tags payments
// @Accept json
// @Produce json
// @Param request body CreateCardPaymentRequest true "Card payment creation request"
// @Success 200 {object} CreateCardPaymentResponse
// @Failure 400 {object} ErrorResponse "Невалидное тело запроса"
// @Failure 422 {object} ErrorResponse "Сумма должна быть отрицательной"
// @Failure 500 {object} ErrorResponse "Не удалось создать платёж"
// @Router /payments/card [post]
func (h *Handler) CreateCardPayment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateCardPaymentRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, "Невалидный JSON")
		return
	}

	if req.Amount.LessThan(MinimalPaymentAmount) {
		SendJSONErr(ctx, w, http.StatusUnprocessableEntity,
			fmt.Errorf("not positive amount %s", req.Amount), "Сумма должна быть не менее 1000 рублей")
		return
	}

	cardPayment, err := h.s.CreateCardPayment(ctx, req.Amount)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Не удалось создать платеж")
		return
	}

	SendJSON(ctx, w, http.StatusOK, CreateCardPaymentResponse{
		Payment: cardPayment,
	})
}

type InvoiceURLResponse struct {
	InvoiceURL string `json:"invoiceURL"`
}

// @Summary Get invoice URL
// @Description Retrieves the invoice URL associated with a transaction ID
// @Tags invoices
// @Accept json
// @Produce json
// @Param txId path string true "Transaction ID (UUID)"
// @Success 200 {object} InvoiceURLResponse
// @Failure 400 {object} ErrorResponse "'txId' должен быть UUID"
// @Failure 404 {object} ErrorResponse "Транзакция не найдена"
// @Failure 500 {object} ErrorResponse "Внутренняя ошибка"
// @Router /payments/invoices/{txId} [get]
func (h *Handler) InvoiceURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	txID, err := uuid.FromString(chi.URLParam(r, "txId"))
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, "'txId' должен быть UUID")
		return
	}

	tx, err := h.s.Transaction(ctx, txID)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			SendJSONErr(ctx, w, http.StatusNotFound, err, "Транзакция не найдена")
		} else {
			SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Внутренняя ошибка")
		}

		return
	}

	SendJSON(ctx, w, http.StatusOK, InvoiceURLResponse{InvoiceURL: tx.InvoiceURL})
}

type CardPaymentCallbackRequest struct {
	OrderNumber string // our transaction id (UUID)
	SignAlias   string
	Checksum    string
	MdOrder     string
	Operation   string
	Status      string
}

type CardPaymentCallbackResponse struct{}

// @Summary Handle payment callback
// @Description Handles a payment callback for the specified transaction
// @Tags payments
// @Accept json
// @Produce json
// @Param orderNumber query string true "Order TxID (UUID)"
// @Param sign_alias query string true "Signature Alias"
// @Param checksum query string true "Checksum (SHA512)"
// @Param mdOrder query string true "MD Order ID"
// @Param operation query string true "Operation Type"
// @Param status query string true "Transaction Status"
// @Success 200 {object} CardPaymentCallbackResponse "Callback обработан успешно"
// @Failure 400 {object} ErrorResponse "Неверные параметры запроса"
// @Failure 403 {object} ErrorResponse "Проверка контрольной суммы не пройдена"
// @Failure 500 {object} ErrorResponse "Ошибка обработки запроса"
// @Router /payments/callbacks/card [get]
func (h *Handler) CardPaymentCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := CardPaymentCallbackRequest{
		OrderNumber: r.URL.Query().Get("orderNumber"),
		SignAlias:   r.URL.Query().Get("sign_alias"),
		Checksum:    r.URL.Query().Get("checksum"),
		MdOrder:     r.URL.Query().Get("mdOrder"),
		Operation:   r.URL.Query().Get("operation"),
		Status:      r.URL.Query().Get("status"),
	}

	err := h.validateCardCallbackCert(req)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusForbidden, fmt.Errorf("validate callback checksum: %w", err), "Проверка контрольной суммы не пройдена")
		return
	}

	txID, err := uuid.FromString(req.OrderNumber)
	if err != nil {
		SendJSONErr(ctx, w, http.StatusBadRequest, err, "Неверные параметры запроса")
		return
	}

	err = h.s.CardPaymentPaid(ctx, txID)
	if err != nil {
		if errors.Is(err, entity.ErrAlreadyPaid) {
			SendJSON(ctx, w, http.StatusOK, CardPaymentCallbackResponse{})
		} else {
			SendJSONErr(ctx, w, http.StatusInternalServerError, err, "Ошибка обработки запроса")
		}

		return
	}

	SendJSON(ctx, w, http.StatusOK, CardPaymentCallbackResponse{})
}

func (h *Handler) validateCardCallbackCert(req CardPaymentCallbackRequest) error {
	if !h.cardCallbackCheckEnabled {
		return nil
	}

	binarySignature, err := hex.DecodeString(req.Checksum)
	if err != nil {
		return fmt.Errorf("decode hex checksum signature: %w", err)
	}

	params := []string{req.MdOrder, req.Operation, req.OrderNumber, req.Status}
	slices.Sort(params)

	data := strings.Join(params, ";") + ";"

	hashedData := sha512.Sum512([]byte(data))

	err = rsa.VerifyPKCS1v15(h.cardCallbackPublicKey, crypto.SHA512, hashedData[:], binarySignature)
	if err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	return nil
}
