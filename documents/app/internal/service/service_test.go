package service_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"github.com/samandr77/microservices/documents/internal/entity"
	"github.com/samandr77/microservices/documents/internal/mocks"
	"github.com/samandr77/microservices/documents/internal/repository"
	"github.com/samandr77/microservices/documents/internal/service"
	"github.com/samandr77/microservices/documents/pkg/postgres"
	"go.uber.org/mock/gomock"
)

type TestService struct {
	repo      *repository.Repository
	roback    *mocks.MockRoback
	clients   *mocks.MockClients
	campaigns *mocks.MockCampaigns
	oneC      *mocks.MockOneC
	s3Client  *mocks.MockS3
	s         *service.Service
}

func NewTestService(t *testing.T) *TestService {
	t.Helper()

	r := require.New(t)
	ctx := context.Background()

	pool, err := postgres.Connect(ctx, os.Getenv("TEST_POSTGRES_DSN"), 10)
	r.NoError(err)

	t.Cleanup(pool.Close)

	ctrl := gomock.NewController(t)
	mockRoback := mocks.NewMockRoback(ctrl)
	mockClients := mocks.NewMockClients(ctrl)
	mockCampaigns := mocks.NewMockCampaigns(ctrl)
	mockOneC := mocks.NewMockOneC(ctrl)
	mockS3 := mocks.NewMockS3(ctrl)

	repo := repository.New(pool)

	s := service.New(
		mockClients,
		mockCampaigns,
		mockRoback,
		mockOneC,
		mockS3,
		repo,
		"",
	)

	return &TestService{
		repo:      repo,
		roback:    mockRoback,
		clients:   mockClients,
		campaigns: mockCampaigns,
		oneC:      mockOneC,
		s3Client:  mockS3,
		s:         s,
	}
}

func TestService_GetDocumentsList(t *testing.T) { //nolint:funlen
	t.Parallel()
	r := require.New(t)
	ts := NewTestService(t)

	ctx := context.Background()
	clientID := uuid.Must(uuid.NewV4())

	firstDocument := entity.Document{
		ID:         uuid.Must(uuid.NewV4()),
		Name:       "a doc",
		ClientID:   clientID,
		ClientName: "a client",
		DocType:    entity.DocTypeUPD,
		Status:     entity.DocStatusCreated,
		CreatedAt:  time.Date(2022, 1, 1, 0, 0, 0, 0, time.Local),
		SignedAt:   nil,
		Sum:        nil,
		URL:        "",
		OneCGuid:   uuid.Must(uuid.NewV4()),
		Data:       entity.ClosingDocumentsData{},
	}

	secondDocument := entity.Document{
		ID:         uuid.Must(uuid.NewV4()),
		Name:       "b doc",
		ClientID:   clientID,
		ClientName: "b client",
		DocType:    entity.DocTypeOferta,
		Status:     entity.DocStatusCreated,
		CreatedAt:  time.Date(2023, 1, 2, 0, 0, 0, 0, time.Local),
		SignedAt:   nil,
		Sum:        nil,
		URL:        "",
		OneCGuid:   uuid.Must(uuid.NewV4()),
		Data:       entity.ClosingDocumentsData{},
	}

	testUser := entity.User{
		ID: uuid.Must(uuid.NewV4()),
		Role: entity.UserRole{
			Name: entity.RoleUser,
		},
	}

	err := ts.repo.CreateDocuments(ctx, firstDocument, secondDocument)
	r.NoError(err)

	tests := []struct {
		name           string
		userInCtx      entity.User
		filter         entity.DocumentsFilter
		mockBehavior   func()
		wantTotalCount int
		wantDocuments  []entity.Document
		wantErr        error
	}{
		{
			name:      "sort by name asc",
			userInCtx: testUser,
			mockBehavior: func() {
				ts.clients.EXPECT().GetClientOwner(gomock.Any(), clientID).Return(entity.ClientOwner{ID: testUser.ID}, nil)
			},
			filter: entity.DocumentsFilter{
				ClientID: clientID,
				Page:     1,
				Limit:    2,
				SortBy:   entity.SortByName,
				OrderBy:  entity.ASC,
			},
			wantTotalCount: 2,
			wantDocuments: []entity.Document{
				firstDocument,
				secondDocument,
			},
			wantErr: nil,
		},
		{
			name:      "sort by created_at desc",
			userInCtx: testUser,
			mockBehavior: func() {
				ts.clients.EXPECT().GetClientOwner(gomock.Any(), clientID).Return(entity.ClientOwner{ID: testUser.ID}, nil)
			},
			filter: entity.DocumentsFilter{
				ClientID: clientID,
				Page:     1,
				Limit:    2,
				SortBy:   entity.SortByCreatedAt,
				OrderBy:  entity.DESC,
			},
			wantTotalCount: 2,
			wantDocuments: []entity.Document{
				secondDocument,
				firstDocument,
			},
			wantErr: nil,
		},
		{
			name:      "sort by doc_type asc",
			userInCtx: testUser,
			mockBehavior: func() {
				ts.clients.EXPECT().GetClientOwner(gomock.Any(), clientID).Return(entity.ClientOwner{ID: testUser.ID}, nil)
			},
			filter: entity.DocumentsFilter{
				ClientID: clientID,
				Page:     1,
				Limit:    1,
				SortBy:   entity.SortByDocType,
				OrderBy:  entity.ASC,
			},
			wantTotalCount: 2,
			wantDocuments: []entity.Document{
				secondDocument,
			},
			wantErr: nil,
		},
		{
			name: "user is manager",
			userInCtx: entity.User{
				ID: uuid.Must(uuid.NewV4()),
				Role: entity.UserRole{
					Name: entity.RoleManager,
				},
			},
			mockBehavior: func() {
				ts.clients.EXPECT().GetClientOwner(gomock.Any(), clientID).Return(entity.ClientOwner{ID: testUser.ID}, nil)
			},
			filter: entity.DocumentsFilter{
				ClientID: clientID,
				Page:     1,
				Limit:    1,
				SortBy:   entity.SortByDocType,
				OrderBy:  entity.ASC,
			},
			wantTotalCount: 2,
			wantDocuments: []entity.Document{
				secondDocument,
			},
			wantErr: nil,
		},
		{
			name: "user is not client owner or manager",
			userInCtx: entity.User{
				ID: uuid.Must(uuid.NewV4()),
				Role: entity.UserRole{
					Name: entity.RoleUser,
				},
			},
			mockBehavior: func() {
				ts.clients.EXPECT().GetClientOwner(gomock.Any(), clientID).Return(entity.ClientOwner{ID: testUser.ID}, nil)
			},
			filter: entity.DocumentsFilter{
				ClientID: clientID,
				Page:     1,
				Limit:    1,
				SortBy:   entity.SortByDocType,
				OrderBy:  entity.ASC,
			},
			wantTotalCount: 0,
			wantDocuments:  nil,
			wantErr:        entity.ErrForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			newCtx := entity.SetUserToContext(context.Background(), tt.userInCtx)
			tt.mockBehavior()

			gotDocuments, gotTotalCount, err := ts.s.GetDocumentsList(newCtx, tt.filter)
			if tt.wantErr != nil {
				r.ErrorIs(err, tt.wantErr)
			} else {
				r.NoError(err)
			}

			r.Equal(tt.wantTotalCount, gotTotalCount)
			r.Equal(tt.wantDocuments, gotDocuments)
		})
	}
}
