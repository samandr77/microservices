package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/samandr77/microservices/payment/internal/entity"
	"github.com/samandr77/microservices/payment/pkg/transport"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout:   time.Second,
			Transport: transport.NewJWTRoundTripper(http.DefaultTransport),
		},
	}
}

type UserClientResponse struct {
	Client   UserClient `json:"client"`
	Oferta   Oferta     `json:"oferta"`
	Employee Employee   `json:"employee"`
}

type Employee struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Email           string    `json:"email"`
	Position        string    `json:"position"`
	Role            string    `json:"orgRole"`
	ClientID        uuid.UUID `json:"clientID"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	StatusChangedAt time.Time `json:"statusChangedAt"`
	UserID          uuid.UUID `json:"userID"`
}

type UserClient struct {
	ID                       uuid.UUID  `json:"id"`
	Name                     string     `json:"name"`
	OGRN                     string     `json:"ogrn"`
	KPP                      string     `json:"kpp"`
	INN                      string     `json:"inn"`
	DocumentFlowType         bool       `json:"documentFlowType"`
	EdoOperator              uuid.UUID  `json:"edoOperator"`
	LegalAddress             Address    `json:"legalAddress"`
	IsActualAddressSameLegal bool       `json:"isActualAddressSameLegal"`
	ActualAddress            Address    `json:"actualAddress"`
	BIC                      string     `json:"bic"`
	AccountNumber            string     `json:"accountNumber"`
	BankName                 string     `json:"bankName"`
	CorrespondentAccount     string     `json:"correspondentAccount"`
	ContractStatus           bool       `json:"contractStatus"`
	Role                     string     `json:"role"`
	Type                     string     `json:"type"`
	Status                   string     `json:"status"`
	OneCGUID                 *uuid.UUID `json:"OneCGUID"`
	IsBlocked                bool       `json:"isBlocked"`
	ManagerRuss              uuid.UUID  `json:"managerRuss"`
	IsSentToCheck            bool       `json:"isSentToCheck"`
	CreatedAt                time.Time  `json:"createdAt"`
	UpdatedAt                time.Time  `json:"updatedAt"`
	ShortName                string     `json:"shortName"`
	Email                    string     `json:"email"`
	Phone                    string     `json:"phone"`
}

type Address struct {
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	Index   string `json:"index"`
	Street  string `json:"street"`
}

type Oferta struct {
	ID         uuid.UUID  `json:"id,omitempty"`
	ClientID   uuid.UUID  `json:"clientId,omitempty"`
	ClientName string     `json:"clientName,omitempty"`
	Name       string     `json:"name,omitempty"`
	DocType    string     `json:"docType,omitempty"`
	Status     string     `json:"status,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	SignedAt   *time.Time `json:"signedAt,omitempty"`
	URL        string     `json:"url,omitempty"`
	OneCGuid   uuid.UUID  `json:"oneCGuid,omitempty"`
}

func (c *Client) UserClient(ctx context.Context, userID uuid.UUID) (entity.Client, error) {
	reqURL := fmt.Sprintf("%s/api/internal/organization?userID=%s", c.baseURL, userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return entity.Client{}, fmt.Errorf("create request: %w", err)
	}

	jwt := entity.JWTFromCtx(ctx)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return entity.Client{}, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.Client{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return entity.Client{}, entity.ErrNotFound
		}

		return entity.Client{}, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, body)
	}

	var data UserClientResponse

	err = json.Unmarshal(body, &data)
	if err != nil {
		return entity.Client{}, fmt.Errorf("decode response: %w", err)
	}

	var guid uuid.UUID
	if data.Client.OneCGUID != nil {
		guid = *data.Client.OneCGUID
	}

	return entity.Client{
		ID:        data.Client.ID,
		GUID:      guid,
		Name:      data.Client.Name,
		ShortName: data.Client.ShortName,
		INN:       data.Client.INN,
		OGRN:      data.Client.OGRN,
		KPP:       data.Client.KPP,
		Status:    entity.ClientStatus(data.Client.Status),
		Oferta: entity.ClientOferta{
			Status: entity.OfertaStatus(data.Oferta.Status),
		},
		Employee: entity.Employee{
			ID:              data.Employee.ID,
			Name:            data.Employee.Name,
			Email:           data.Employee.Email,
			Position:        data.Employee.Position,
			Role:            entity.EmployeeRole(data.Employee.Role),
			ClientID:        data.Employee.ClientID,
			Status:          entity.EmployeeStatus(data.Employee.Status),
			CreatedAt:       data.Employee.CreatedAt,
			StatusChangedAt: data.Employee.StatusChangedAt,
			UserID:          data.Employee.UserID,
		},
		Address: entity.Address(data.Client.LegalAddress),
	}, nil
}

type ClientsByGUIDsRequest struct {
	GUIDs []uuid.UUID `json:"guids"`
}

type ClientsByGUIDsResponse struct {
	Clients []struct {
		ID   uuid.UUID `json:"id"`
		GUID uuid.UUID `json:"guid"`
		Name string    `json:"name"`
		INN  string    `json:"inn"`
		OGRN string    `json:"ogrn"`
	} `json:"clients"`
}

func (c *Client) ClientsByGUIDs(ctx context.Context, guids []uuid.UUID) (map[uuid.UUID]entity.Client, error) {
	b, err := json.Marshal(ClientsByGUIDsRequest{
		GUIDs: guids,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/internal/organization/guids", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	jwt := entity.JWTFromCtx(ctx)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, entity.ErrNotFound
		}

		return nil, fmt.Errorf("unexpected status code: %d\n%s", resp.StatusCode, body)
	}

	var user ClientsByGUIDsResponse

	err = json.Unmarshal(body, &user)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	clients := make(map[uuid.UUID]entity.Client, len(user.Clients))
	for _, v := range user.Clients {
		clients[v.GUID] = entity.Client{
			ID:   v.ID,
			GUID: v.GUID,
			Name: v.Name,
			INN:  v.INN,
			OGRN: v.OGRN,
		}
	}

	return clients, nil
}

func (c *Client) GetClientOwner(ctx context.Context, clientID uuid.UUID) (entity.ClientOwner, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/internal/organization/owner?clientID="+clientID.String(), nil)
	if err != nil {
		return entity.ClientOwner{}, fmt.Errorf("create request: %w", err)
	}

	jwt := entity.JWTFromCtx(ctx)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return entity.ClientOwner{}, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.ClientOwner{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return entity.ClientOwner{}, fmt.Errorf("unexpected status code: %d\nbody:%s", resp.StatusCode, body)
	}

	var data entity.ClientOwner

	err = json.Unmarshal(body, &data)
	if err != nil {
		return entity.ClientOwner{}, fmt.Errorf("decode response: %w", err)
	}

	return data, nil
}
