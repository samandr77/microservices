package sberid

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/pkg/config"
)

const (
	rquidBytesLength    = 16
	jwtPartsCount       = 3
	defaultRetryWaitMax = time.Second * 5
)

type ClientInterface interface {
	ExchangeCodeForTokens(ctx context.Context, authCode, redirectURI string) (*TokenResponse, error)
	GetUserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error)
	ValidateIDToken(idToken string, expectedNonce string) (*IDTokenClaims, error)
}

type Client struct {
	client       *http.Client
	baseURL      string
	tokenURL     string
	userInfoURL  string
	clientID     string
	clientSecret string
}

var _ ClientInterface = (*Client)(nil)

func NewClient(cfg config.Config) *Client {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = cfg.SberID.RetryAttempts
	retryClient.RetryWaitMin = 1 * time.Second
	retryClient.RetryWaitMax = defaultRetryWaitMax
	retryClient.HTTPClient.Timeout = cfg.SberID.Timeout

	retryClient.Logger = nil

	retryClient.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if err != nil {
			return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
		}

		return false, nil
	}

	if cfg.SberID.CACert != "" {
		caCert, err := os.ReadFile(cfg.SberID.CACert)
		if err != nil {
			log.Panicf("failed to load Sber ID CA cert: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Panic("failed to append Sber ID CA cert to pool")
		}

		tlsConfig := &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		}

		if cfg.SberID.ClientCert != "" && cfg.SberID.ClientKey != "" {
			log.Printf("Loading Sber ID client certificate - %s, %s", cfg.SberID.ClientCert, cfg.SberID.ClientKey)

			certificate, err := tls.LoadX509KeyPair(cfg.SberID.ClientCert, cfg.SberID.ClientKey)
			if err != nil {
				log.Panicf("could not load Sber ID client certificate: %v", err)
			}

			tlsConfig.Certificates = []tls.Certificate{certificate}
		}

		retryClient.HTTPClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	return &Client{
		client:       retryClient.StandardClient(),
		baseURL:      cfg.SberID.BaseURL,
		tokenURL:     cfg.SberID.TokenURL,
		userInfoURL:  cfg.SberID.UserInfoURL,
		clientID:     cfg.SberID.ClientID,
		clientSecret: cfg.SberID.ClientSecret,
	}
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

type UserInfoResponse struct {
	Sub         string `json:"sub"`
	SubAlt      string `json:"sub_alt"`
	Email       string `json:"email"`
	FamilyName  string `json:"family_name"`
	GivenName   string `json:"given_name"`
	MiddleName  string `json:"middle_name,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Birthdate   string `json:"birthdate,omitempty"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`

	HTTPCode        string `json:"httpCode"`
	HTTPMessage     string `json:"httpMessage"`
	MoreInformation string `json:"moreInformation"`
}

type IDTokenClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	SubAlt   string `json:"sub_alt"`
	Aud      string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	AuthTime int64  `json:"auth_time"`
	Nonce    string `json:"nonce"`
}

func (c *Client) ExchangeCodeForTokens(ctx context.Context, authCode, redirectURI string) (*TokenResponse, error) {
	endpoint := c.tokenURL

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("client_id", c.clientID)
	data.Set("client_secret", c.clientSecret)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Rquid", generateRquid())

	resp, err := c.client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "connection refused") {
			return nil, entity.ErrSberIDServiceUnavailable
		}
		return nil, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		apiErr := ParseSberIDError(resp.StatusCode, body)
		return nil, apiErr
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &tokenResp, nil
}

func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	endpoint := c.userInfoURL

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Introspect-Rquid", generateRquid())

	resp, err := c.client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "connection refused") {
			return nil, entity.ErrSberIDServiceUnavailable
		}
		return nil, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		apiErr := ParseSberIDError(resp.StatusCode, body)
		return nil, apiErr
	}

	var userInfo UserInfoResponse
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	userInfo.Email = normalizeSberEmail(userInfo.Email)

	if userInfo.PhoneNumber != "" {
		userInfo.PhoneNumber = normalizeSberPhone(userInfo.PhoneNumber)
	}

	userInfo.GivenName = normalizeSberName(userInfo.GivenName)
	userInfo.FamilyName = normalizeSberName(userInfo.FamilyName)

	if userInfo.MiddleName != "" {
		userInfo.MiddleName = normalizeSberName(userInfo.MiddleName)
	}

	if userInfo.Birthdate != "" {
		userInfo.Birthdate = normalizeSberBirthdate(userInfo.Birthdate)
	}

	return &userInfo, nil
}

func generateRquid() string {
	bytes := make([]byte, rquidBytesLength)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}

	return hex.EncodeToString(bytes)
}

func ParseSberIDError(statusCode int, body []byte) error {
	var errorResp ErrorResponse
	if err := json.Unmarshal(body, &errorResp); err != nil {
		return mapHTTPStatusToError(statusCode)
	}

	errorCode := errorResp.Error
	if errorCode == "" {
		errorCode = errorResp.MoreInformation
	}

	description := strings.ToLower(errorResp.ErrorDescription)
	if description == "" {
		description = strings.ToLower(errorResp.HTTPMessage)
	}

	switch errorCode {
	case "invalid_grant":
		if strings.Contains(description, "expired") || strings.Contains(description, "просрочен") {
			return entity.ErrSberIDCodeExpired
		}

		return entity.ErrSberIDInvalidCode

	case "invalid_request":
		if strings.Contains(description, "redirect_uri") {
			return entity.ErrSberIDInvalidRequest
		}

		if strings.Contains(description, "state") {
			return entity.ErrSberIDInvalidRequest
		}

		if strings.Contains(description, "rquid") {
			return entity.ErrSberIDInvalidRequest
		}

		return entity.ErrSberIDInvalidCode

	case "invalid_client", "unauthorized_client", "Mismatch client_id":
		return entity.ErrSberIDInvalidClient

	case "invalid_scope", "insufficient_scope", "Scope not supported by 3rd party":
		return entity.ErrSberIDScopeInsufficient

	case "invalid_token", "unauthorized":
		if strings.Contains(description, "expired") || strings.Contains(description, "использован") {
			return entity.ErrSberIDAccessTokenExpired
		}

		return entity.ErrSberIDInvalidAccessToken

	case "Rate Limit exceeded":
		return entity.ErrSberIDRateLimitExceeded

	case "Forbidden":
		return entity.ErrSberIDForbidden

	case "No resources match requested URI":
		return entity.ErrSberIDNotFound

	default:
		return mapHTTPStatusToError(statusCode)
	}
}

func mapHTTPStatusToError(statusCode int) error {
	switch statusCode {
	case http.StatusBadRequest:
		return entity.ErrSberIDInvalidRequest
	case http.StatusUnauthorized:
		return entity.ErrSberIDInvalidAccessToken
	case http.StatusForbidden:
		return entity.ErrSberIDForbidden
	case http.StatusNotFound:
		return entity.ErrSberIDNotFound
	case http.StatusTooManyRequests:
		return entity.ErrSberIDRateLimitExceeded
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return entity.ErrSberIDServiceUnavailable
	default:
		return fmt.Errorf("sber id error: status %d", statusCode)
	}
}

func (c *Client) ValidateIDToken(idToken string, expectedNonce string) (*IDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != jwtPartsCount {
		return nil, fmt.Errorf("invalid id token format: expected %d parts, got %d", jwtPartsCount, len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode id token payload: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal id token claims: %w", err)
	}

	if claims.Nonce != expectedNonce {
		return nil, entity.ErrSberIDInvalidNonce
	}

	now := time.Now().Unix()
	if claims.Exp < now {
		return nil, entity.ErrSberIDAccessTokenExpired
	}

	if claims.Iat > now+60 {
		return nil, errors.New("id token issued in the future")
	}

	return &claims, nil
}

func normalizeSberEmail(email string) string {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)
	email = strings.ReplaceAll(email, "(", "")
	email = strings.ReplaceAll(email, ")", "")
	email = strings.ReplaceAll(email, "[", "")
	email = strings.ReplaceAll(email, "]", "")
	email = strings.ReplaceAll(email, "<", "")
	email = strings.ReplaceAll(email, ">", "")

	return email
}

func normalizeSberPhone(phone string) string {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "(", "")
	phone = strings.ReplaceAll(phone, ")", "")
	phone = strings.ReplaceAll(phone, "-", "")
	phone = strings.ReplaceAll(phone, "+", "")

	return phone
}

func normalizeSberName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}

	runes := []rune(name)
	for i := range runes {
		if i == 0 {
			runes[i] = []rune(strings.ToUpper(string(runes[i])))[0]
		} else {
			runes[i] = []rune(strings.ToLower(string(runes[i])))[0]
		}
	}

	return string(runes)
}

func normalizeSberBirthdate(birthdate string) string {
	birthdate = strings.TrimSpace(birthdate)
	if birthdate == "" {
		return birthdate
	}

	t, err := time.Parse("2006-01-02", birthdate)
	if err != nil {
		return birthdate
	}

	return t.Format("02.01.2006")
}
