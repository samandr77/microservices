package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/samandr77/microservices/documents/internal/entity"
)

//go:generate go run go.uber.org/mock/mockgen@latest -source=service.go -destination=../mocks/service.go -package=mocks -typed

type Repository interface {
	DocumentByClientIDAndType(ctx context.Context, clientID uuid.UUID, documentType entity.DocType) (entity.Document, error)
	SignOferta(ctx context.Context, clientID uuid.UUID, signedAt time.Time) error
	DocumentsListByFilter(ctx context.Context, filter entity.DocumentsFilter) ([]entity.Document, int, error)
	DocumentByID(ctx context.Context, documentID uuid.UUID) (entity.Document, error)
	SaveClosingDocumentsRequest(ctx context.Context, closingDocReq entity.ClosingDocumentsRequest) error
	GetClosingDocumentsRequestByGUID(ctx context.Context, guid uuid.UUID) (entity.ClosingDocumentsRequest, error)
	CreateDocuments(ctx context.Context, documents ...entity.Document) error
	ChangeClosingDocumentsRequestStatus(ctx context.Context, guid uuid.UUID) error
	UpdateDocumentsStatus(ctx context.Context, oldStatus, newStatus entity.DocStatus, signedAt time.Time, olderThan time.Time) error
	DocumentByClientID(ctx context.Context, id uuid.UUID) (entity.Document, error)
}

type Campaigns interface {
	GetCampaigns(ctx context.Context, clientID uuid.UUID, startDate time.Time, endDate time.Time) ([]entity.CampaignInfo, error)
	ActualCampaignInfo(ctx context.Context, info entity.Report) error
}

type Clients interface {
	GetClientsInfo(ctx context.Context, id uuid.UUID) (entity.Client, error)
	GetClientOwner(ctx context.Context, clientID uuid.UUID) (entity.ClientOwner, error)
	GetUserClient(ctx context.Context, userID uuid.UUID) (entity.Client, error)
}

type OneC interface {
	GenerateDocuments(ctx context.Context, report entity.Report, guid uuid.UUID, campaignsInfo []entity.CampaignInfo) error
}

type S3 interface {
	DownloadDocument(ctx context.Context, url string) ([]byte, error)
}

type Service struct {
	clients     Clients
	campaigns   Campaigns
	roBack      Roback
	oneC        OneC
	s3Client    S3
	repo        Repository
	ofertaS3URl string
}

type Roback interface {
	GetBroadcastReport(ctx context.Context, campaignIDs []int64, dateFrom time.Time, dateTo time.Time) (entity.Report, error)
}

func New(
	client Clients,
	campaign Campaigns,
	roBack Roback,
	oneC OneC,
	s3Client S3,
	repo Repository,
	ofertaS3URL string,

) *Service {
	return &Service{
		clients:     client,
		campaigns:   campaign,
		roBack:      roBack,
		oneC:        oneC,
		s3Client:    s3Client,
		repo:        repo,
		ofertaS3URl: ofertaS3URL,
	}
}

func (s *Service) CreateOferta(ctx context.Context, clientID uuid.UUID, clientName string, oneCguid uuid.UUID) error {
	userFromCtx, err := entity.UserFromContext(ctx)
	if err != nil {
		return fmt.Errorf("get user from context: %w", err)
	}

	clientOwner, err := s.clients.GetClientOwner(ctx, clientID)
	if err != nil {
		return fmt.Errorf("get client owner: %w", err)
	}

	if userFromCtx.Role.Name != entity.RoleManager && clientOwner.ID != userFromCtx.ID {
		return fmt.Errorf("%w: user %s is not manager or client owner", entity.ErrForbidden, userFromCtx.ID)
	}

	_, err = s.repo.DocumentByClientIDAndType(ctx, clientID, entity.DocTypeOferta)
	if err == nil {
		return entity.ErrAlreadyExists
	}

	oferta := entity.Document{
		ID:         uuid.Must(uuid.NewV4()),
		ClientID:   clientID,
		ClientName: clientName,
		Name:       "Оферта",
		DocType:    entity.DocTypeOferta,
		CreatedAt:  time.Now(),
		Status:     entity.DocStatusCreated,
		OneCGuid:   oneCguid,
		URL:        s.ofertaS3URl,
	}

	err = s.repo.CreateDocuments(ctx, oferta)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, fmt.Sprintf("Создание оферты для организации %s", clientID))

	return nil
}

func (s *Service) SignOferta(ctx context.Context, clientID uuid.UUID) error {
	userFromContext, err := entity.UserFromContext(ctx)
	if err != nil {
		return fmt.Errorf("get user from context: %w", err)
	}

	clientOwner, err := s.clients.GetClientOwner(ctx, clientID)
	if err != nil {
		return fmt.Errorf("get client owner: %w", err)
	}

	if clientOwner.ID != userFromContext.ID && userFromContext.Role.Name != entity.RoleManager {
		return fmt.Errorf("%w: user %s is not manager or client owner", entity.ErrForbidden, userFromContext.ID)
	}

	doc, err := s.repo.DocumentByClientIDAndType(ctx, clientID, entity.DocTypeOferta)
	if err != nil {
		return err
	}

	if doc.Status == entity.DocStatusSigned {
		return nil
	}

	signedAt := time.Now()

	err = s.repo.SignOferta(ctx, clientID, signedAt)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, fmt.Sprintf("Акцептование оферты организации %s", clientID))

	return nil
}

func (s *Service) GetDocumentsList(ctx context.Context, filter entity.DocumentsFilter) ([]entity.Document, int, error) {
	userFromContext, err := entity.UserFromContext(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("get user from context: %w", err)
	}

	clientOwner, err := s.clients.GetClientOwner(ctx, filter.ClientID)
	if err != nil {
		return nil, 0, fmt.Errorf("get client owner: %w", err)
	}

	if userFromContext.Role.Name != entity.RoleManager && clientOwner.ID != userFromContext.ID {
		return nil, 0, fmt.Errorf("%w: user %s is not manager or client owner", entity.ErrForbidden, userFromContext.ID)
	}

	return s.repo.DocumentsListByFilter(ctx, filter)
}

func (s *Service) GetDocumentDetails(ctx context.Context, documentID uuid.UUID) (entity.Document, error) {
	return s.repo.DocumentByID(ctx, documentID)
}
func (s *Service) CreatClosingDocuments(ctx context.Context, clientID uuid.UUID, dateFrom time.Time, dateTo time.Time) error {
	clientInfo, err := s.clients.GetClientsInfo(ctx, clientID)
	if err != nil {
		return err
	}

	campaignsInfo, err := s.campaigns.GetCampaigns(ctx, clientID, dateFrom, dateTo)
	if err != nil {
		return err
	}

	campaignIDs := make([]int64, 0, len(campaignsInfo))

	for _, v := range campaignsInfo {
		campaignIDs = append(campaignIDs, v.CampaignID)
	}

	report, err := s.roBack.GetBroadcastReport(ctx, campaignIDs, dateFrom, dateTo)
	if err != nil {
		return err
	}

	err = s.campaigns.ActualCampaignInfo(ctx, report)
	if err != nil {
		return err
	}

	err = s.oneC.GenerateDocuments(ctx, report, clientInfo.OneCGuid, campaignsInfo)
	if err != nil {
		return err
	}

	now := time.Now()
	closingDocReq := entity.ClosingDocumentsRequest{
		ID:         uuid.Must(uuid.NewV4()),
		ClientID:   clientID,
		ClientName: clientInfo.Name,
		Status:     entity.RequestPending,
		OneCGuid:   clientInfo.OneCGuid,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	err = s.repo.SaveClosingDocumentsRequest(ctx, closingDocReq)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, fmt.Sprintf("Формирование закрывающих документов для организации %s", clientID))

	return nil
}

func (s *Service) ClosingDocuments(ctx context.Context, doc entity.ClosingDocuments) error {
	reqInfo, err := s.repo.GetClosingDocumentsRequestByGUID(ctx, doc.GUID)
	if err != nil {
		return err
	}

	documents := make([]entity.Document, 0, len(doc.Data))

	for i, v := range doc.Data {
		document := entity.Document{
			ID:         uuid.Must(uuid.NewV4()),
			ClientID:   reqInfo.ClientID,
			ClientName: reqInfo.ClientName,
			Name:       "Закрывающие документы",
			DocType:    entity.DocTypeUPD,
			Status:     entity.DocStatusCreated,
			CreatedAt:  time.Now(),
			SignedAt:   nil,
			Sum:        ptr(v.ServicesList[i].TotalAmount),
			URL:        doc.URL,
			Data:       v,
			OneCGuid:   reqInfo.OneCGuid,
		}

		documents = append(documents, document)
	}

	err = s.repo.CreateDocuments(ctx, documents...)
	if err != nil {
		return err
	}

	err = s.repo.ChangeClosingDocumentsRequestStatus(ctx, reqInfo.OneCGuid)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) SignDocuments(ctx context.Context) error {
	const fiveDays = time.Hour * 24 * 5
	fiveDaysAgo := time.Now().Add(fiveDays)

	err := s.repo.UpdateDocumentsStatus(ctx, entity.DocStatusCreated, entity.DocStatusSigned, time.Now(), fiveDaysAgo)
	if err != nil {
		return fmt.Errorf("update document status: %w", err)
	}

	return nil
}

func (s *Service) DownloadDocument(ctx context.Context, documentID uuid.UUID) (entity.DownloadedDocument, error) {
	doc, err := s.repo.DocumentByID(ctx, documentID)
	if err != nil {
		return entity.DownloadedDocument{}, err
	}

	data, err := s.s3Client.DownloadDocument(ctx, doc.URL)
	if err != nil {
		return entity.DownloadedDocument{}, err
	}

	return entity.DownloadedDocument{
		Name: doc.Name,
		Data: data,
	}, nil
}

func (s *Service) DocumentByClientID(ctx context.Context, id uuid.UUID) (entity.Document, error) {
	userFromCtx, err := entity.UserFromContext(ctx)
	if err != nil {
		return entity.Document{}, fmt.Errorf("get user from context: %w", err)
	}

	_, err = s.clients.GetUserClient(ctx, userFromCtx.ID)
	if err != nil && !errors.Is(err, entity.ErrNotFound) {
		return entity.Document{}, fmt.Errorf("get client owner: %w", err)
	}

	if userFromCtx.Role.Name != entity.RoleManager && errors.Is(err, entity.ErrNotFound) {
		return entity.Document{}, fmt.Errorf("%w: user %s is not manager or client employee", entity.ErrForbidden, userFromCtx.ID)
	}

	doc, err := s.repo.DocumentByClientID(ctx, id)
	if err != nil {
		return entity.Document{}, fmt.Errorf("get document by client %s: %w", id, err)
	}

	return doc, nil
}

func ptr[T any](v T) *T {
	return &v
}
