package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/samandr77/microservices/documents/internal/entity"
)

type Client struct {
	client *http.Client
	url    string
}

func NewClient(url string) *Client {
	const timeout = time.Second * 5

	return &Client{
		client: &http.Client{
			Timeout: timeout,
		},
		url: url,
	}
}

type GetClientsInfoResponse struct {
	ID        uuid.UUID `json:"ID"`
	Name      string    `json:"name"`
	INN       string    `json:"inn"`
	Status    string    `json:"status"`
	OneCGuid  uuid.UUID `json:"oneCGuid"`
	CreatedAt time.Time `json:"createdAt"`
}

func (c *Client) GetClientsInfo(ctx context.Context, id uuid.UUID) (entity.Client, error) {
	url := fmt.Sprintf("%s/api/organizationInfo?clientId=%s", c.url, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return entity.Client{}, fmt.Errorf("create request: %w", err)
	}

	token, err := entity.TokenFromContext(ctx)
	if err != nil {
		return entity.Client{}, fmt.Errorf("get token from ctx: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return entity.Client{}, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return entity.Client{},
			fmt.Errorf("%w: cient with id %s not found: status %d", entity.ErrNotFound, id, resp.StatusCode)
	}

	if resp.StatusCode == http.StatusInternalServerError {
		return entity.Client{}, err
	}

	var data GetClientsInfoResponse

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return entity.Client{}, fmt.Errorf("decode response: %w", err)
	}

	return clientInfoFromAPI(data), nil
}

func clientInfoFromAPI(client GetClientsInfoResponse) entity.Client {
	return entity.Client{
		ID:        client.ID,
		Name:      client.Name,
		INN:       client.INN,
		Status:    client.Status,
		OneCGuid:  client.OneCGuid,
		CreatedAt: client.CreatedAt,
	}
}

func (c *Client) GetClientOwner(ctx context.Context, clientID uuid.UUID) (entity.ClientOwner, error) {
	url := fmt.Sprintf("%s/api/internal/organization/owner?clientID=%s", c.url, clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return entity.ClientOwner{}, fmt.Errorf("create request: %w", err)
	}

	token, err := entity.TokenFromContext(ctx)
	if err != nil {
		return entity.ClientOwner{}, fmt.Errorf("get token from ctx: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return entity.ClientOwner{}, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return entity.ClientOwner{}, fmt.Errorf("unexpected code %d", resp.StatusCode)
	}

	var data entity.ClientOwner

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return entity.ClientOwner{}, fmt.Errorf("decode response: %w", err)
	}

	return data, nil
}

type GetUserClientRequest struct {
	UserIDs []uuid.UUID `json:"userIDs"`
}

type GetUserClientResponse struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

func (c *Client) GetUserClient(ctx context.Context, userID uuid.UUID) (entity.Client, error) {
	url := fmt.Sprintf("%s/api/internal/user/organizations", c.url) //nolint:perfsprint

	body, err := json.Marshal(GetUserClientRequest{
		UserIDs: []uuid.UUID{userID},
	})

	if err != nil {
		return entity.Client{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return entity.Client{}, fmt.Errorf("create request: %w", err)
	}

	token, err := entity.TokenFromContext(ctx)
	if err != nil {
		return entity.Client{}, fmt.Errorf("get token from ctx: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return entity.Client{}, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return entity.Client{}, fmt.Errorf("%w: cient with id %s not found: status %d", entity.ErrNotFound, userID, resp.StatusCode)
	default:
		return entity.Client{}, fmt.Errorf("unexpected code %d", resp.StatusCode)
	}

	var data []GetUserClientResponse

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return entity.Client{}, fmt.Errorf("decode response: %w", err)
	}

	return entity.Client{
		ID:   data[0].ID,
		Name: data[0].Name,
	}, nil
}
