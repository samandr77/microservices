package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/samandr77/microservices/payment/internal/entity"
	"github.com/samandr77/microservices/payment/pkg/transport"

	"github.com/gofrs/uuid/v5"
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

type UserIDByTokenRequest struct {
	Token string `json:"accessToken"`
}

type UserIDByTokenResponse struct {
	ID          uuid.UUID       `json:"id"`
	LastName    string          `json:"lastName"`
	FirstName   string          `json:"firstName"`
	MiddleName  string          `json:"middleName"`
	Email       string          `json:"email"`
	PhoneNumber string          `json:"phoneNumber"`
	Role        entity.UserRole `json:"role"`
	Position    string          `json:"position"`
}

func (c *Client) User(ctx context.Context, token string) (entity.User, error) {
	j, err := json.Marshal(UserIDByTokenRequest{Token: token})
	if err != nil {
		return entity.User{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/validate", bytes.NewReader(j))
	if err != nil {
		return entity.User{}, fmt.Errorf("create request: %w", err)
	}

	jwt := entity.JWTFromCtx(ctx)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return entity.User{}, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return entity.User{}, fmt.Errorf("unexpected status code: %d\nbody: %s", resp.StatusCode, body)
	}

	var data UserIDByTokenResponse

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return entity.User{}, fmt.Errorf("decode response: %w", err)
	}

	return entity.User{
		ID:        data.ID,
		FirstName: data.FirstName,
		LastName:  data.LastName,
		Email:     data.Email,
		Role:      data.Role,
	}, nil
}
