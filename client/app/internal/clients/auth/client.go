package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/samandr77/microservices/client/internal/entity"
	"github.com/samandr77/microservices/client/pkg/config"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient(baseURL string, cfg config.Config) *Client {
	const timeout = time.Second * 5

	client := &http.Client{
		Timeout: timeout,
	}

	if cfg.MTLSEnabled {
		ctx := context.Background()

		caCert, err := os.ReadFile(cfg.CACert)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to load CA cert", "error", err, "ca_cert_path", cfg.CACert)
			panic(fmt.Sprintf("load CA cert: %v", err))
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			slog.ErrorContext(ctx, "Failed to append CA cert to pool", "ca_cert_path", cfg.CACert)
			panic("failed to append CA cert to pool")
		}

		clientCert := cfg.ClientCert
		clientKey := cfg.ClientKey
		slog.InfoContext(ctx, "Loading mTLS key pairs", "client_cert", clientCert, "client_key", clientKey)

		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to load certificate", "error", err, "client_cert", clientCert, "client_key", clientKey)
			panic(fmt.Sprintf("could not load certificate: %v", err))
		}

		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{certificate},
				MinVersion:   tls.VersionTLS12,
			},
		}
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 -- Required for dev environment
				MinVersion:         tls.VersionTLS12,
			},
		}
	}

	return &Client{
		baseURL: baseURL,
		http:    client,
	}
}

type ValidateTokenRequest struct {
	AccessToken string `json:"access_token"`
}

type ValidateTokenResponse struct {
	UserID string `json:"user_id"`
}

func (c *Client) User(ctx context.Context, token string) (entity.User, error) {
	reqBody := ValidateTokenRequest{AccessToken: token}
	j, err := json.Marshal(reqBody)

	if err != nil {
		return entity.User{}, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + "/api/token/validate"
	slog.DebugContext(ctx, "auth client: sending request", "url", url)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
		bytes.NewReader(j),
	)
	if err != nil {
		return entity.User{}, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Name", "blago-user")

	resp, err := c.http.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "auth client: HTTP request to auth service failed", "url", url, "error", err)
		return entity.User{}, fmt.Errorf("do request to auth service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.ErrorContext(ctx, "auth client: unexpected status from auth service",
			"url", url,
			"status_code", resp.StatusCode,
			"response_body", string(body))

		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return entity.User{}, fmt.Errorf("%w: %s", entity.ErrUnauthorized, body)
		case http.StatusForbidden:
			return entity.User{}, fmt.Errorf("%w: %s", entity.ErrUserBlocked, body)
		case http.StatusGone:
			return entity.User{}, fmt.Errorf("%w: %s", entity.ErrUserDeleted, body)
		default:
			return entity.User{}, fmt.Errorf("unexpected status code from auth service: %d, body: %s", resp.StatusCode, body)
		}
	}

	slog.DebugContext(ctx, "auth client: token validated successfully", "url", url)

	var data ValidateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return entity.User{}, fmt.Errorf("decode response from auth service: %w", err)
	}

	userID, err := uuid.FromString(data.UserID)
	if err != nil {
		return entity.User{}, fmt.Errorf("parse user_id from auth service response: %w", err)
	}

	return entity.User{
		UserID: userID,
	}, nil
}

type DestroyTokenRequest struct {
	SessionToken string `json:"session_token"`
}

func (c *Client) DestroyToken(ctx context.Context, accessToken string) error {
	reqBody := DestroyTokenRequest{SessionToken: accessToken}
	j, err := json.Marshal(reqBody)

	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + "/api/token/destroy"
	slog.InfoContext(ctx, "auth client: destroying token", "url", url)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
		bytes.NewReader(j),
	)
	if err != nil {
		slog.ErrorContext(ctx, "auth client: failed to create destroy token request", "url", url, "error", err)
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Name", "blago-user")

	resp, err := c.http.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "auth client: HTTP request to auth service failed", "url", url, "error", err)
		return fmt.Errorf("do request to auth service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code from auth service: %d, body: %s", resp.StatusCode, body)
	}

	return nil
}

type DestroyTokensByUserIDRequest struct {
	UserID string `json:"user_id"`
}

func (c *Client) DestroyTokensByUserID(ctx context.Context, userID uuid.UUID) error {
	reqBody := DestroyTokensByUserIDRequest{UserID: userID.String()}
	j, err := json.Marshal(reqBody)

	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + "/internal/api/token/destroy"
	slog.InfoContext(ctx, "auth client: destroying tokens by user ID", "user_id", userID, "url", url)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		url,
		bytes.NewReader(j),
	)
	if err != nil {
		slog.ErrorContext(ctx, "auth client: failed to create destroy tokens request", "url", url, "error", err)
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Name", "blago-user")

	resp, err := c.http.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "auth client: HTTP request to auth service failed", "url", url, "error", err)
		return fmt.Errorf("do request to auth service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.ErrorContext(ctx, "auth client: unexpected status from auth service",
			"url", url,
			"status_code", resp.StatusCode,
			"response_body", string(body))
		return fmt.Errorf("unexpected status code from auth service: %d, body: %s", resp.StatusCode, body)
	}

	slog.InfoContext(ctx, "auth client: successfully destroyed tokens by user ID", "user_id", userID, "url", url)

	return nil
}
