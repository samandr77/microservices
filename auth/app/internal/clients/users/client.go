package users

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/samandr77/microservices/auth/internal/entity"
	"github.com/samandr77/microservices/auth/pkg/config"
)

type Client struct {
	client *http.Client
	url    string
}

func NewClient(url string, cfg config.Config) *Client {
	const timeout = time.Second * 5

	client := &http.Client{
		Timeout: timeout,
	}

	if cfg.MTLSEnabled {
		caCert, err := os.ReadFile(cfg.CACert)
		if err != nil {
			log.Panicf("load CA cert: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Panic("failed to append CA cert to pool")
		}

		clientCert := cfg.ClientCert
		clientKey := cfg.ClientKey
		log.Printf("Load key pairs - %s, %s", clientCert, clientKey)

		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			log.Panicf("could not load certificate: %v", err)
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
				MinVersion: tls.VersionTLS12,
			},
		}
	}

	return &Client{
		client: client,
		url:    url,
	}
}

type CreateUserResponse struct {
	UserID uuid.UUID `json:"user_id"`
}

type CreateUserRequest struct {
	Email                 string  `json:"email"`
	FirstName             string  `json:"first_name"`
	LastName              string  `json:"last_name"`
	MiddleName            string  `json:"middle_name,omitempty"`
	Phone                 *string `json:"phone,omitempty"`
	Birthdate             *string `json:"birthdate,omitempty"`
	Sub                   *string `json:"sub,omitempty"`
	SubAlt                *string `json:"sub_alt,omitempty"`
	City                  *string `json:"city,omitempty"`
	SchoolName            *string `json:"school_name,omitempty"`
	PlaceOfEducation      *string `json:"place_of_education,omitempty"`
	AddressReg            *string `json:"address_reg,omitempty"`
	Series                *string `json:"series,omitempty"`
	Number                *string `json:"number,omitempty"`
	IssuedBy              *string `json:"issued_by,omitempty"`
	IssuedDate            *string `json:"issued_date,omitempty"`
	Code                  *string `json:"code,omitempty"`
	PersonalInfo          *string `json:"personal_info,omitempty"`
	PrivacyPolicyAgreed   bool    `json:"privacy_policy_agreed"`
	NewsletterAgreed      bool    `json:"newsletter_agreed"`
	PublicDonationsAgreed bool    `json:"public_donations_agreed"`
}

func (s *Client) CreateUser(ctx context.Context, req CreateUserRequest) (uuid.UUID, error) {
	url := s.url + "/internal/users/create"

	jsonData, err := json.Marshal(req)

	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal request in JSON: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return uuid.Nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return uuid.Nil, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return uuid.Nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode == http.StatusConflict {
		return uuid.Nil, fmt.Errorf("code 409: %s", body)
	}

	if resp.StatusCode != http.StatusCreated {
		return uuid.Nil, fmt.Errorf("code 500: %s", body)
	}

	var data CreateUserResponse

	err = json.Unmarshal(body, &data)
	if err != nil {
		return uuid.Nil, fmt.Errorf("decode response: %w", err)
	}

	return data.UserID, nil
}

type UserByEmailResponse struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Status   string `json:"status"`
	RoleID   string `json:"role_id"`
	RoleName string `json:"role_name"`
}

func (s *Client) UserByEmail(ctx context.Context, email string) (entity.UserInfo, error) {
	url := s.url + "/internal/users?email=" + email

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var data UserByEmailResponse

		err = json.Unmarshal(body, &data)
		if err != nil {
			return entity.UserInfo{}, fmt.Errorf("decode response: %w", err)
		}

		userID, err := uuid.FromString(data.UserID)
		if err != nil {
			return entity.UserInfo{}, fmt.Errorf("decode user_id: %w", err)
		}

		roleID := uuid.Nil
		if data.RoleID != "" {
			roleID, err = uuid.FromString(data.RoleID)
			if err != nil {
				return entity.UserInfo{}, fmt.Errorf("decode role_id: %w", err)
			}
		}

		return entity.UserInfo{
			ID:        userID,
			Email:     data.Email,
			Role:      entity.UserRole{ID: roleID, Name: data.RoleName},
			IsBlocked: false,
		}, nil
	case http.StatusNotFound:
		return entity.UserInfo{}, entity.ErrNotFound
	case http.StatusForbidden:
		return entity.UserInfo{}, entity.ErrUserBlocked
	case http.StatusGone:
		return entity.UserInfo{}, entity.ErrUserDeleted
	default:
		return entity.UserInfo{}, fmt.Errorf("unexpected code %d\n%s", resp.StatusCode, body)
	}
}

func (s *Client) SearchUser(ctx context.Context, email, sub, subAlt string) (entity.UserInfo, error) {
	const maxUserSearchParams = 3
	q := make([]string, 0, maxUserSearchParams)

	if email != "" {
		q = append(q, "email="+email)
	}

	if sub != "" {
		q = append(q, "sub="+sub)
	}

	if subAlt != "" {
		q = append(q, "sub_alt="+subAlt)
	}

	url := s.url + "/internal/users"
	if len(q) > 0 {
		url += "?" + strings.Join(q, "&")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var userInfo UserInfoByIDResponse
		if err := json.Unmarshal(body, &userInfo); err != nil {
			return entity.UserInfo{}, fmt.Errorf("decode response: %w\n%s", err, body)
		}

		return userInfoByIDResponseFromAPI(userInfo), nil
	case http.StatusNotFound:
		return entity.UserInfo{}, entity.ErrNotFound
	case http.StatusForbidden:
		return entity.UserInfo{}, entity.ErrUserBlocked
	case http.StatusGone:
		return entity.UserInfo{}, entity.ErrUserDeleted
	default:
		return entity.UserInfo{}, fmt.Errorf("unexpected code %d\n%s", resp.StatusCode, body)
	}
}

type UpdateUserRequest struct {
	UserID                *uuid.UUID `json:"user_id,omitempty"`
	Email                 string     `json:"email"`
	FirstName             string     `json:"first_name,omitempty"`
	LastName              string     `json:"last_name,omitempty"`
	MiddleName            string     `json:"middle_name,omitempty"`
	Phone                 *string    `json:"phone,omitempty"`
	Birthdate             *string    `json:"birthdate,omitempty"`
	Sub                   *string    `json:"sub,omitempty"`
	SubAlt                *string    `json:"sub_alt,omitempty"`
	City                  *string    `json:"city,omitempty"`
	SchoolName            *string    `json:"school_name,omitempty"`
	PlaceOfEducation      *string    `json:"place_of_education,omitempty"`
	AddressReg            *string    `json:"address_reg,omitempty"`
	Series                *string    `json:"series,omitempty"`
	Number                *string    `json:"number,omitempty"`
	IssuedBy              *string    `json:"issued_by,omitempty"`
	IssuedDate            *string    `json:"issued_date,omitempty"`
	Code                  *string    `json:"code,omitempty"`
	PersonalInfo          *string    `json:"personal_info,omitempty"`
	PrivacyPolicyAgreed   bool       `json:"privacy_policy_agreed"`
	NewsletterAgreed      bool       `json:"newsletter_agreed"`
	PublicDonationsAgreed bool       `json:"public_donations_agreed"`
}

func (s *Client) UpdateUser(ctx context.Context, req UpdateUserRequest) error {
	url := s.url + "/internal/users/update"

	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request in JSON: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusNotFound {
		return entity.ErrNotFound
	}

	return fmt.Errorf("unexpected code %d: %s", resp.StatusCode, body)
}

func userInfoByIDResponseFromAPI(user UserInfoByIDResponse) entity.UserInfo {
	role := entity.UserRole{}

	if user.RoleID != "" {
		roleID, err := uuid.FromString(user.RoleID)
		if err == nil {
			role.ID = roleID
		}
	}

	role.Name = user.RoleName

	return entity.UserInfo{
		ID:          user.ID,
		LastName:    user.LastName,
		FirstName:   user.FirstName,
		MiddleName:  user.MiddleName,
		Email:       user.Email,
		PhoneNumber: user.PhoneNumber,
		Role:        role,
		Position:    user.Position,
		IsBlocked:   user.IsBlocked,
	}
}

type UserInfoByIDResponse struct {
	ID          uuid.UUID `json:"user_id"`
	LastName    string    `json:"last_name"`
	FirstName   string    `json:"first_name"`
	MiddleName  string    `json:"middle_name"`
	Email       string    `json:"email"`
	PhoneNumber string    `json:"phone_number"`
	RoleID      string    `json:"role_id"`
	RoleName    string    `json:"role_name"`
	Position    string    `json:"position"`
	IsBlocked   bool      `json:"is_blocked"`
}

func (s *Client) UserInfoByID(ctx context.Context, userID uuid.UUID) (entity.UserInfo, error) {
	url := fmt.Sprintf("%s/internal/users/%s", s.url, userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.UserInfo{}, fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var userInfo UserInfoByIDResponse

		err = json.Unmarshal(body, &userInfo)
		if err != nil {
			return entity.UserInfo{}, fmt.Errorf("decode response: %w\n%s", err, body)
		}

		return userInfoByIDResponseFromAPI(userInfo), nil
	case http.StatusNotFound:
		return entity.UserInfo{}, entity.ErrNotFound
	case http.StatusForbidden:
		return entity.UserInfo{}, entity.ErrUserBlocked
	case http.StatusGone:
		return entity.UserInfo{}, entity.ErrUserDeleted
	default:
		return entity.UserInfo{}, fmt.Errorf("unexpected code %d\n%s", resp.StatusCode, body)
	}
}

type BlockUserRequest struct {
	UserID               uuid.UUID `json:"user_id"`
	BlockDurationSeconds *int64    `json:"blockDurationSeconds,omitempty"`
}

func (s *Client) BlockUserTemporary(ctx context.Context, id uuid.UUID, blockedTo time.Time) error {
	url := s.url + "/internal/users/temporary-block"

	now := time.Now()

	var blockDurationSeconds *int64

	if blockedTo.After(now) {
		duration := int64(blockedTo.Sub(now).Seconds())
		blockDurationSeconds = &duration
	}

	jsonData, err := json.Marshal(BlockUserRequest{
		UserID:               id,
		BlockDurationSeconds: blockDurationSeconds,
	})
	if err != nil {
		return fmt.Errorf("marshal request in JSON: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected code %d: %s", resp.StatusCode, body)
	}

	return nil
}
