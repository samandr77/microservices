package sberid

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/pkg/config"
)

// Helper function to create test config
func newTestConfig(baseURL, clientID, clientSecret string, timeout time.Duration, retryAttempts int) config.Config {
	return config.Config{
		SberID: config.SberIDConfig{
			BaseURL:       baseURL,
			TokenURL:      baseURL, // in tests, the mock server handles all paths
			UserInfoURL:   baseURL, // in tests, the mock server handles all paths
			ClientID:      clientID,
			ClientSecret:  clientSecret,
			Timeout:       timeout,
			RetryAttempts: retryAttempts,
			// CACert is empty for tests, so mTLS will be skipped
		},
	}
}

//nolint:gocognit,funlen // test function with multiple test cases
func TestClient_ExchangeCodeForTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		authCode       string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		expectError    error
		checkResponse  func(*testing.T, *TokenResponse)
		retryAttempts  int
	}{
		{
			name:     "successful token exchange",
			authCode: "valid-code",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Rquid") == "" {
					t.Error("Missing rquid header")
				}
				if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Error("Wrong Content-Type header")
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"access_token": "test-access-token",
					"token_type": "bearer",
					"expires_in": 60,
					"scope": "openid email",
					"id_token": "test-id-token",
					"refresh_token": "test-refresh-token"
				}`))
			},
			expectError: nil,
			checkResponse: func(t *testing.T, resp *TokenResponse) {
				t.Helper()
				if resp.AccessToken != "test-access-token" {
					t.Errorf("Expected access_token 'test-access-token', got '%s'", resp.AccessToken)
				}
				if resp.ExpiresIn != 60 {
					t.Errorf("Expected expires_in 60, got %d", resp.ExpiresIn)
				}
			},
		},
		{
			name:     "invalid authorization code",
			authCode: "invalid-code",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid code"}`))
			},
			expectError: entity.ErrSberIDInvalidCode,
		},
		{
			name:     "expired authorization code",
			authCode: "expired-code",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"moreInformation":"invalid_grant","httpMessage":"Code expired"}`))
			},
			expectError: entity.ErrSberIDCodeExpired,
		},
		{
			name:     "invalid client credentials",
			authCode: "valid-code",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Invalid client"}`))
			},
			expectError: entity.ErrSberIDInvalidClient,
		},
		{
			name:     "rate limit exceeded",
			authCode: "valid-code",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"moreInformation":"Rate Limit exceeded"}`))
			},
			expectError:   entity.ErrSberIDRateLimitExceeded,
			retryAttempts: 0,
		},
		{
			name:     "service unavailable",
			authCode: "valid-code",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"service_unavailable"}`))
			},
			expectError:   entity.ErrSberIDServiceUnavailable,
			retryAttempts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.serverResponse(w, r)
			}))
			defer server.Close()

			retries := 1

			if tt.retryAttempts > 0 || tt.expectError != nil {
				retries = tt.retryAttempts
			}

			cfg := newTestConfig(server.URL, "test-client", "test-secret", 5*time.Second, retries)
			client := NewClient(cfg)

			resp, err := client.ExchangeCodeForTokens(context.Background(), tt.authCode, "test-uri")

			if tt.expectError != nil {
				if err == nil {
					t.Fatalf("Expected error %v, got nil", tt.expectError)
				}

				if !errors.Is(err, tt.expectError) {
					t.Errorf("Expected error %v, got %v", tt.expectError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}

				if tt.checkResponse != nil {
					tt.checkResponse(t, resp)
				}
			}
		})
	}
}

//nolint:funlen // test function with multiple test cases
func TestClient_GetUserInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		accessToken    string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		expectError    error
		checkResponse  func(*testing.T, *UserInfoResponse)
	}{
		{
			name:        "successful user info",
			accessToken: "valid-token",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				auth := r.Header.Get("Authorization")
				if !strings.HasPrefix(auth, "Bearer ") {
					t.Error("Missing or invalid Authorization header")
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"sub": "test-sub-123",
					"sub_alt": "test-sub-alt-456",
					"email": "user@example.com",
					"family_name": "Тестов",
					"given_name": "Тест",
					"middle_name": "Тестович",
					"phone_number": "+79991234567"
				}`))
			},
			expectError: nil,
			checkResponse: func(t *testing.T, resp *UserInfoResponse) {
				t.Helper()
				if resp.Sub != "test-sub-123" {
					t.Errorf("Expected sub 'test-sub-123', got '%s'", resp.Sub)
				}
				if resp.Email != "user@example.com" {
					t.Errorf("Expected email 'user@example.com', got '%s'", resp.Email)
				}
				if resp.FamilyName != "Тестов" {
					t.Errorf("Expected family_name 'Тестов', got '%s'", resp.FamilyName)
				}
			},
		},
		{
			name:        "invalid access token",
			accessToken: "invalid-token",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"Invalid access token"}`))
			},
			expectError: entity.ErrSberIDInvalidAccessToken,
		},
		{
			name:        "expired access token",
			accessToken: "expired-token",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"Token expired"}`))
			},
			expectError: entity.ErrSberIDAccessTokenExpired,
		},
		{
			name:        "insufficient scope",
			accessToken: "valid-token",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"Scope not supported"}`))
			},
			expectError: entity.ErrSberIDScopeInsufficient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.serverResponse(w, r)
			}))
			defer server.Close()

			cfg := newTestConfig(server.URL, "test-client", "test-secret", 5*time.Second, 1)
			client := NewClient(cfg)

			resp, err := client.GetUserInfo(context.Background(), tt.accessToken)

			if tt.expectError != nil {
				if err == nil {
					t.Fatalf("Expected error %v, got nil", tt.expectError)
				}

				if !errors.Is(err, tt.expectError) {
					t.Errorf("Expected error %v, got %v", tt.expectError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}

				if tt.checkResponse != nil {
					tt.checkResponse(t, resp)
				}
			}
		})
	}
}

func TestGenerateRquid(t *testing.T) {
	t.Parallel()

	rquid1 := generateRquid()
	rquid2 := generateRquid()

	if len(rquid1) != 32 {
		t.Errorf("Expected rquid length 32, got %d", len(rquid1))
	}

	if rquid1 == rquid2 {
		t.Error("Expected unique rquid values")
	}

	_, err := hex.DecodeString(rquid1)
	if err != nil {
		t.Errorf("Expected valid hex string, got error: %v", err)
	}
}

func TestParseSberIDError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       []byte
		wantError  error
	}{
		{
			name:       "invalid grant - code expired",
			statusCode: http.StatusBadRequest,
			body:       []byte(`{"error":"invalid_grant","error_description":"Code expired"}`),
			wantError:  entity.ErrSberIDCodeExpired,
		},
		{
			name:       "invalid grant - invalid code",
			statusCode: http.StatusBadRequest,
			body:       []byte(`{"error":"invalid_grant","error_description":"Invalid authorization code"}`),
			wantError:  entity.ErrSberIDInvalidCode,
		},
		{
			name:       "invalid client",
			statusCode: http.StatusUnauthorized,
			body:       []byte(`{"error":"invalid_client","error_description":"Invalid client credentials"}`),
			wantError:  entity.ErrSberIDInvalidClient,
		},
		{
			name:       "invalid token - expired",
			statusCode: http.StatusUnauthorized,
			body:       []byte(`{"error":"invalid_token","error_description":"Token expired"}`),
			wantError:  entity.ErrSberIDAccessTokenExpired,
		},
		{
			name:       "invalid token - invalid",
			statusCode: http.StatusUnauthorized,
			body:       []byte(`{"error":"invalid_token","error_description":"Invalid access token"}`),
			wantError:  entity.ErrSberIDInvalidAccessToken,
		},
		{
			name:       "insufficient scope",
			statusCode: http.StatusForbidden,
			body:       []byte(`{"error":"insufficient_scope","error_description":"Scope insufficient"}`),
			wantError:  entity.ErrSberIDScopeInsufficient,
		},
		{
			name:       "rate limit exceeded",
			statusCode: http.StatusTooManyRequests,
			body:       []byte(`{"error":"rate_limit","error_description":"Too many requests"}`),
			wantError:  entity.ErrSberIDRateLimitExceeded,
		},
		{
			name:       "service unavailable",
			statusCode: http.StatusServiceUnavailable,
			body:       []byte(`{"error":"service_unavailable","error_description":"Service temporarily unavailable"}`),
			wantError:  entity.ErrSberIDServiceUnavailable,
		},
		{
			name:       "forbidden",
			statusCode: http.StatusForbidden,
			body:       []byte(`{"moreInformation":"Forbidden"}`),
			wantError:  entity.ErrSberIDForbidden,
		},
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
			body:       []byte(`{"moreInformation":"No resources match requested URI"}`),
			wantError:  entity.ErrSberIDNotFound,
		},
		{
			name:       "invalid request - Token endpoint format",
			statusCode: http.StatusBadRequest,
			body:       []byte(`{"httpCode":"400","httpMessage":"Bad Request","moreInformation":"invalid_request"}`),
			wantError:  entity.ErrSberIDInvalidCode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ParseSberIDError(tt.statusCode, tt.body)
			if !errors.Is(err, tt.wantError) {
				t.Errorf("ParseSberIDError() = %v, want %v", err, tt.wantError)
			}
		})
	}
}

func TestClient_ValidateIDToken(t *testing.T) {
	t.Parallel()

	now := time.Now().Unix()
	future := now + 3600

	validPayload := []byte(
		`{"sub":"123","sub_alt":"456","aud":"client-id","iss":"id.sber.ru","nonce":"test-nonce","exp":` +
			toString(future) + `,"iat":` + toString(now) + `}`,
	)
	expiredPayload := []byte(`{"sub":"123","nonce":"test-nonce","exp":` + toString(now-3600) + `,"iat":` + toString(now-3600) + `}`)
	wrongNoncePayload := []byte(`{"sub":"123","nonce":"wrong-nonce","exp":` + toString(future) + `,"iat":` + toString(now) + `}`)

	validToken := "eyJhbGciOiJub25lIn0." + base64Encode(validPayload) + "."
	expiredToken := "eyJhbGciOiJub25lIn0." + base64Encode(expiredPayload) + "."
	wrongNonceToken := "eyJhbGciOiJub25lIn0." + base64Encode(wrongNoncePayload) + "."

	cfg := newTestConfig("https://test.com", "test-client", "test-secret", 5*time.Second, 1)
	client := NewClient(cfg)

	tests := []struct {
		name          string
		idToken       string
		expectedNonce string
		wantError     error
	}{
		{
			name:          "valid id token",
			idToken:       validToken,
			expectedNonce: "test-nonce",
			wantError:     nil,
		},
		{
			name:          "expired id token",
			idToken:       expiredToken,
			expectedNonce: "test-nonce",
			wantError:     entity.ErrSberIDAccessTokenExpired,
		},
		{
			name:          "wrong nonce",
			idToken:       wrongNonceToken,
			expectedNonce: "test-nonce",
			wantError:     entity.ErrSberIDInvalidNonce,
		},
		{
			name:          "invalid format",
			idToken:       "invalid-token",
			expectedNonce: "test-nonce",
			wantError:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			claims, err := client.ValidateIDToken(tt.idToken, tt.expectedNonce)

			if tt.wantError != nil {
				if err == nil {
					t.Fatalf("Expected error %v, got nil", tt.wantError)
				}

				if !errors.Is(err, tt.wantError) {
					t.Errorf("Expected error %v, got %v", tt.wantError, err)
				}
			} else if tt.name != "invalid format" {
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}

				if claims == nil {
					t.Fatal("Expected claims, got nil")
				}

				if claims.Sub != "123" {
					t.Errorf("Expected sub '123', got '%s'", claims.Sub)
				}
			}
		})
	}
}

func toString(i int64) string {
	return strconv.FormatInt(i, 10)
}

func base64Encode(data []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return encoded
}
