package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/samandr77/microservices/documents/internal/entity"
	"github.com/samandr77/microservices/documents/internal/service"
)

type Service interface {
	CreateOferta(ctx context.Context, clientID uuid.UUID, clientName string, oneCguid uuid.UUID) error
	SignOferta(ctx context.Context, clientID uuid.UUID) error
	GetDocumentsList(ctx context.Context, filter entity.DocumentsFilter) ([]entity.Document, int, error)
	GetDocumentDetails(ctx context.Context, documentID uuid.UUID) (entity.Document, error)
	CreatClosingDocuments(ctx context.Context, clientID uuid.UUID, dateFrom time.Time, dateTo time.Time) error
	ClosingDocuments(ctx context.Context, doc entity.ClosingDocuments) error
	DownloadDocument(ctx context.Context, documentID uuid.UUID) (entity.DownloadedDocument, error)
	DocumentByClientID(ctx context.Context, id uuid.UUID) (entity.Document, error)
}

// @title Documents API
// @version 1.0
// @description This is an API for client management.
// @BasePath /api
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

type Handler struct {
	s Service
}

func NewHandler(s Service) *Handler {
	return &Handler{
		s,
	}
}

// Health godoc
// @Summary      Проверка состояния сервиса
// @Description  Возвращает статус работы сервиса
// @Tags         health
// @Success      200 {string} string "Сервис работает!"
// @Failure      500 {object} ResponseError "Сервис не работает"
// @Router       /health [get]
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := w.Write([]byte("Сервис работает!\n"))
	if err != nil {
		SendErr(ctx, w, http.StatusInternalServerError, err, "Сервис не работает!")
	}
}

type CreateOfertaRequest struct {
	ClientID   uuid.UUID `json:"clientId"`
	ClientName string    `json:"clientName"`
	OneCGUID   uuid.UUID `json:"oneCguid"`
}

type CreateOfertaResponse struct {
	Message string `json:"message"`
}

// CreateOferta godoc
// @Summary      Создание оферты
// @Description  Создает новую оферту для клиента
// @Tags         oferta
// @Accept       json
// @Produce      json
// @Param        request body CreateOfertaRequest true "Параметры оферты"
// @Success      200 {object} CreateOfertaResponse "Оферта успешно создана"
// @Failure      400 {object} ResponseError "Некорректный запрос"
// @Failure      403 {object} ResponseError "Недостаточно прав"
// @Failure      409 {object} ResponseError "Оферта уже существует"
// @Failure      500 {object} ResponseError "Ошибка сервера"
// @Router       /oferta [post]
func (h *Handler) CreateOferta(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateOfertaRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	err = service.ValidateCreateOfertaParams(req.ClientID, req.ClientName, req.OneCGUID)
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	err = h.s.CreateOferta(ctx, req.ClientID, req.ClientName, req.OneCGUID)
	if err != nil {
		if errors.Is(err, entity.ErrAlreadyExists) {
			SendErr(ctx, w, http.StatusConflict, err, "Оферта для этого клиента уже существует")
			return
		}

		if errors.Is(err, entity.ErrForbidden) {
			SendErr(ctx, w, http.StatusForbidden, err, "Недостаточно прав")
			return
		}

		SendErr(ctx, w, http.StatusInternalServerError, err, "ошибка при создании оферты")

		return
	}

	SendJSON(ctx, w, http.StatusOK, CreateOfertaResponse{
		Message: "оферта успешно создана",
	})
}

type SignOfertaRequest struct {
	ClientID uuid.UUID `json:"clientID"`
}

type SignOfertaResponse struct {
	Message string `json:"message"`
}

// SignOferta godoc
// @Summary      Подписание оферты
// @Description  Изменяет статус оферты на подписанный
// @Tags         oferta
// @Accept       json
// @Produce      json
// @Param        request body SignOfertaRequest true "Параметры для подписи оферты"
// @Success      200 {object} SignOfertaResponse "Статус оферты успешно изменен"
// @Failure      403 {object} ResponseError "Недостаточно прав"
// @Failure      400 {object} ResponseError "Некорректный запрос"
// @Failure      404 {object} ResponseError "Оферта не найдена"
// @Failure      500 {object} ResponseError "Ошибка сервера"
// @Router       /oferta/sign [put]
func (h *Handler) SignOferta(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SignOfertaRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	if req.ClientID.IsNil() {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	err = h.s.SignOferta(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			SendErr(ctx, w, http.StatusNotFound, err, "Оферта для этого клиента не существует")
			return
		}

		if errors.Is(err, entity.ErrForbidden) {
			SendErr(ctx, w, http.StatusForbidden, err, "Недостаточно прав для изменения статуса оферты")
			return
		}

		SendErr(ctx, w, http.StatusInternalServerError, err, "ошибка при изменении статуса")

		return
	}

	SendJSON(ctx, w, http.StatusOK, SignOfertaResponse{
		Message: "статус оферты успешно изменен",
	})
}

type GetDocumentsListResponse struct {
	TotalDocuments int               `json:"totalDocuments"`
	Documents      []entity.Document `json:"documents"`
}

// GetDocumentsList godoc
// @Summary      Список документов
// @Description  Возвращает список документов для клиента
// @Tags         documents
// @Accept       json
// @Produce      json
// @Param        clientId query string true "ID клиента"
// @Param        limit query string false "Лимит документов"
// @Param        page query string false "Номер страницы"
// @Param        sortBy query string true "Сортировка документов" Enums(name, doc_type, created_at)
// @Param        orderBy query string true "Направление сортировки, ASC или DESC" Enums(asc, desc)
// @Success      200 {object} GetDocumentsListResponse
// @Failure      400 {object} ResponseError "Некорректные параметры запроса"
// @Failure      403 {object} ResponseError "Недостаточно прав"
// @Failure      404 {object} ResponseError "Документов для этого клиента не существует"
// @Failure      500 {object} ResponseError "Ошибка сервера"
// @Security 	 ApiKeyAuth
// @Param 		 Authorization header string true "Authorization:{accessToken}"
// @Router       /documents/list [get]
func (h *Handler) GetDocumentsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filter, err := parseDocumentsFilter(r.URL.Query())
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректные параметры запроса: "+err.Error())
		return
	}

	documents, totalDocuments, err := h.s.GetDocumentsList(ctx, filter)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			SendErr(ctx, w, http.StatusNotFound, err, "Документов для этого клиента не существует")
			return
		}

		if errors.Is(err, entity.ErrForbidden) {
			SendErr(ctx, w, http.StatusForbidden, err, "Недостаточно прав для получения списка документов")
			return
		}

		SendErr(ctx, w, http.StatusInternalServerError, err, "ошибка при получении списка документов")

		return
	}

	SendJSON(ctx, w, http.StatusOK, GetDocumentsListResponse{
		TotalDocuments: totalDocuments,
		Documents:      documents,
	})
}

func parseDocumentsFilter(url url.Values) (entity.DocumentsFilter, error) {
	qPage := url.Get("page")
	qlimit := url.Get("limit")
	sortBy := entity.DocumentsSortBy(url.Get("sortBy"))
	orderBy := entity.OrderBy(url.Get("orderBy"))

	clientID, err := uuid.FromString(url.Get("clientId"))
	if err != nil {
		return entity.DocumentsFilter{}, fmt.Errorf("невалдный параметр clientId:%s", clientID)
	}

	page, err := strconv.Atoi(qPage)
	if err != nil || page <= 0 || page > 100 {
		page = 1
	}

	limit, err := strconv.Atoi(qlimit)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 20
	}

	if !sortBy.IsValid() {
		return entity.DocumentsFilter{}, fmt.Errorf("невалдный параметр sortBy:%s", sortBy)
	}

	if !orderBy.IsValid() {
		return entity.DocumentsFilter{}, fmt.Errorf("невалдный параметр orderBy:%s", orderBy)
	}

	filter := entity.DocumentsFilter{
		ClientID: clientID,
		Page:     uint64(page),
		Limit:    uint64(limit),
		SortBy:   sortBy,
		OrderBy:  orderBy,
	}

	return filter, nil
}

// GetDocumentDetails godoc
// @Summary      Детали документа
// @Description  Возвращает детали документа
// @Tags         documents
// @Accept       json
// @Produce      json
// @Param        id query string true "ID документа"
// @Success      200 {object} entity.Document
// @Failure      400 {object} ResponseError "Некорректные параметры запроса"
// @Failure      404 {object} ResponseError "Документа c таким ID не существует"
// @Failure      500 {object} ResponseError "Ошибка сервера"
// @Security  	 ApiKeyAuth
// @Param 		 Authorization header string true "Authorization:{accessToken}"
// @Router       /documents/details [get]
func (h *Handler) GetDocumentDetails(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	documentID, err := uuid.FromString(r.URL.Query().Get("id"))
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректные параметры запроса")
		return
	}

	if documentID.IsNil() {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректные параметры запроса, documentID не может быть пустым")
		return
	}

	document, err := h.s.GetDocumentDetails(ctx, documentID)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			SendErr(ctx, w, http.StatusNotFound, err, "Документа c таким ID не существует")
			return
		}

		SendErr(ctx, w, http.StatusInternalServerError, err, "Ошибка при получении деталей документа")

		return
	}

	SendJSON(ctx, w, http.StatusOK, document)
}

type CreatClosingDocumentsRequest struct {
	ClientID uuid.UUID `json:"clientID"`
	DateFrom string    `json:"dateFrom"`
	DateTo   string    `json:"dateTo"`
}

// CreatClosingDocuments godoc
// @Summary      Создание закрывающих документов
// @Description  Создает закрывающие документы за указанный период для клиента
// @Tags         documents
// @Accept       json
// @Produce      json
// @Param        request body CreatClosingDocumentsRequest true "Параметры закрывающих документов"
// @Success      200 {string} string "Закрывающие документы успешно созданы"
// @Failure      400 {object} ResponseError "Некорректный запрос"
// @Failure      404 {object} ResponseError "Данных не найдено"
// @Failure      500 {object} ResponseError "Ошибка сервера"
// @Security     ApiKeyAuth
// @Param 		 Authorization header string true "Authorization:{accessToken}"
// @Router       /getDocuments [post]
func (h *Handler) CreatClosingDocuments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreatClosingDocumentsRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	startDate, err := time.Parse("2006-01-02", req.DateFrom)
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	endDate, err := time.Parse("2006-01-02", req.DateTo)
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	err = h.s.CreatClosingDocuments(ctx, req.ClientID, startDate, endDate)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			SendErr(ctx, w, http.StatusNotFound, err, "Данных не найдено")
			return
		}

		SendErr(ctx, w, http.StatusInternalServerError, err, errInternalRuText)

		return
	}
}

// ClosingDocuments godoc
// @Summary      Обработка закрывающих документов
// @Description  Обрабатывает коллбэк с данными закрывающих документов
// @Tags         documents
// @Accept       json
// @Produce      json
// @Param        request body entity.ClosingDocuments true "Данные закрывающих документов"
// @Success      200 {string} string "Документы успешно обработаны"
// @Failure      400 {object} ResponseError "Некорректный запрос"
// @Failure      500 {object} ResponseError "Ошибка сервера"
// @Security     ApiKeyAuth
// @Param 		 Authorization header string true "Authorization:{accessToken}"
// @Router       /private/act/callback [post]
func (h *Handler) ClosingDocuments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req entity.ClosingDocuments

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректное тело запроса")
		return
	}

	err = h.s.ClosingDocuments(ctx, req)
	if err != nil {
		SendErr(ctx, w, http.StatusInternalServerError, err, errInternalRuText)
		return
	}
}

// DownloadDocument godoc
// @Summary      Скачивание документа
// @Description  Скачивает документ с указанным ID
// @Tags         documents
// @Accept       json
// @Produce      application/pdf
// @Param        id query string true "ID документа"
// @Success      200 {file} binary "PDF документ"
// @Failure      400 {object} ResponseError "Некорректный запрос"
// @Failure      404 {object} ResponseError "Документа c таким ID не существует"
// @Failure      500 {object} ResponseError "Ошибка сервера"
// @Security     ApiKeyAuth
// @Param        Authorization header string true "Authorization:{accessToken}"
// @Router       /documents/download [get]
func (h *Handler) DownloadDocument(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	documentID, err := uuid.FromString(r.URL.Query().Get("id"))
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректные параметры запроса")
		return
	}

	if documentID.IsNil() {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректные параметры запроса, id документа не может быть пустым")
		return
	}

	downloadedDocument, err := h.s.DownloadDocument(ctx, documentID)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			SendErr(ctx, w, http.StatusNotFound, err, "Документа c таким ID не существует")
			return
		}

		SendErr(ctx, w, http.StatusInternalServerError, err, "Ошибка при получении деталей документа")

		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s.pdf", url.QueryEscape(downloadedDocument.Name)))

	http.ServeContent(w, r, downloadedDocument.Name, time.Now(), bytes.NewReader(downloadedDocument.Data))
}

type DocumentsByClientIDRequest struct {
	ID         uuid.UUID        `json:"id"`
	ClientID   uuid.UUID        `json:"clientId"`
	ClientName string           `json:"clientName"`
	Name       string           `json:"name"`
	DocType    string           `json:"docType"`
	Status     string           `json:"status"`
	CreatedAt  time.Time        `json:"createdAt"`
	SignedAt   *time.Time       `json:"signedAt"`
	Sum        *decimal.Decimal `json:"sum"`
	URL        string           `json:"url"`
	OneCGuid   uuid.UUID        `json:"oneCGuid"`
}

// DocumentsByClientID godoc
// @Summary      Документ
// @Description  Возвращает документ по ID клиента
// @Tags         documents
// @Accept       json
// @Produce      json
// @Param        clientId query string true "ID клиента"
// @Success      200 {object} DocumentsByClientIDRequest
// @Failure      400 {object} ResponseError "Некорректные параметры запроса"
// @Failure      403 {object} ResponseError "Недостаточно прав"
// @Failure      404 {object} ResponseError "Документа для данного клиента не существует"
// @Failure      500 {object} ResponseError "Ошибка сервера"
// @Security  	 ApiKeyAuth
// @Param 		 Authorization header string true "Authorization:{accessToken}"
// @Router       /documents [get]
func (h *Handler) DocumentsByClientID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID, err := uuid.FromString(r.URL.Query().Get("clientId"))
	if err != nil {
		SendErr(ctx, w, http.StatusBadRequest, err, "Некорректный clientId: "+err.Error())
		return
	}

	document, err := h.s.DocumentByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			SendErr(ctx, w, http.StatusNotFound, err, "Документа для данного клиента не существует")
			return
		}

		if errors.Is(err, entity.ErrForbidden) {
			SendErr(ctx, w, http.StatusForbidden, err, "Недостаточно прав")
			return
		}

		SendErr(ctx, w, http.StatusInternalServerError, err, errInternalRuText)

		return
	}

	SendJSON(ctx, w, http.StatusOK, documentToAPI(document))
}

func documentToAPI(doc entity.Document) DocumentsByClientIDRequest {
	return DocumentsByClientIDRequest{
		ID:         doc.ID,
		ClientID:   doc.ClientID,
		ClientName: doc.ClientName,
		Name:       doc.Name,
		DocType:    string(doc.DocType),
		Status:     string(doc.Status),
		CreatedAt:  doc.CreatedAt,
		SignedAt:   doc.SignedAt,
		Sum:        doc.Sum,
		URL:        doc.URL,
		OneCGuid:   doc.OneCGuid,
	}
}
