package vtbbank

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"

	"github.com/samandr77/microservices/payment/internal/entity"
	"github.com/samandr77/microservices/payment/pkg/config"
	"github.com/samandr77/microservices/payment/pkg/transport"
)

const oneHundred = 100

type Client struct {
	cfg config.VTBBank
	c   *http.Client
}

func NewClient(cfg config.VTBBank) *Client {
	const timeout = 10 * time.Second

	return &Client{
		cfg: cfg,
		c: &http.Client{
			Timeout:   timeout,
			Transport: transport.NewJWTRoundTripper(http.DefaultTransport),
		},
	}
}

type OneTimeSPBLinkRequest struct {
	AgentID        string   `json:"agentId"`
	MemberID       string   `json:"memberId"`
	Account        string   `json:"account"`
	MerchantID     string   `json:"merchantId"`
	TakeTax        bool     `json:"takeTax"`
	OrderID        string   `json:"orderId"`
	RequestID      string   `json:"requestId"`
	Amount         string   `json:"amount"` // Units
	QrTTL          int      `json:"qrTtl"`
	PaymentPurpose string   `json:"paymentPurpose"`
	RedirectURL    string   `json:"redirectUrl"`
	TotalTaxAmount string   `json:"totalTaxAmount,omitempty"` // Units. Zero is not allowed, null should be used instead.
	Uip            string   `json:"uip"`
	Image          reqImage `json:"image"`
}

type reqImage struct {
	MediaType string `json:"mediaType"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
}

type OneTimeSPBLinkResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		QrcID   string    `json:"qrcId"`
		Payload string    `json:"payload"`
		Status  string    `json:"status"`
		Image   respImage `json:"image"`
	} `json:"data"`
	OrderID   string `json:"orderId"`
	RequestID string `json:"requestId"`
}

type respImage struct {
	MediaType string `json:"mediaType"`
	Content   string `json:"content"`
}

func (c *Client) OneTimeSPBLink(
	ctx context.Context,
	tx entity.Transaction,
	requisites entity.ClientRequisites,
) (entity.SPBLink, error) {
	token, err := c.authToken(ctx)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("get auth token: %w", err)
	}

	oneHundred := decimal.New(oneHundred, 0)
	amount := tx.Amount.Mul(oneHundred).Truncate(0).String() // In units
	taxAmount := tx.Amount.Mul(oneHundred).Truncate(0)       // In units
	ttlSeconds := 600
	imageSizePx := 300

	totalTaxAmount := taxAmount.String()
	if taxAmount.IsZero() {
		totalTaxAmount = ""
	}

	reqData := OneTimeSPBLinkRequest{
		AgentID:        "A11000000010",
		MemberID:       "200000000005",
		Account:        requisites.BankAccountNumber,
		MerchantID:     "MB0000006875",
		TakeTax:        taxAmount.IsPositive(),
		OrderID:        strconv.FormatInt(tx.Number, 10),
		RequestID:      tx.ID.String(),
		Amount:         amount,
		QrTTL:          ttlSeconds,
		PaymentPurpose: fmt.Sprintf("Оплата по договору №%d от %s", tx.Number, tx.CreatedAt.Format("02.01.2006")),
		RedirectURL:    c.cfg.SPBRedirectURL,
		TotalTaxAmount: totalTaxAmount,
		Uip:            "281000670LSS7DN18SJQDNP4B05KLJL2",
		Image: reqImage{
			MediaType: "image/png",
			Width:     imageSizePx,
			Height:    imageSizePx,
		},
	}

	b, err := json.Marshal(reqData)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("marshal request: %w", err)
	}

	reqURL := c.cfg.BaseURL + "/outside/public/web/openapi/kib/spbc/b2bPartners/v1/one-time-link"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(b))
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IBM-Client-Id", c.cfg.ClientID) //nolint:canonicalheader
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.c.Do(req)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return entity.SPBLink{}, fmt.Errorf("bad response status: %s", body)
	}

	var respData OneTimeSPBLinkResponse

	err = json.Unmarshal(body, &respData)
	if err != nil {
		return entity.SPBLink{}, fmt.Errorf("unmarshal response: %w", err)
	}

	result := entity.SPBLink{
		QrcID:   respData.Data.QrcID,
		Payload: respData.Data.Payload,
		Status:  entity.SPBPaymentStatus(respData.Data.Status),
		Image: entity.Image{
			MediaType: respData.Data.Image.MediaType,
			Content:   respData.Data.Image.Content,
		},
		OrderID:   respData.OrderID,
		RequestID: respData.RequestID,
	}

	return result, nil
}

type SPBPaymentStatusRequest struct {
	QID   uuid.UUID `json:"qId"`
	QRCID string    `json:"qrcId"`
}

type SPBPaymentStatusResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	AnID    string `json:"anId"`
	QID     string `json:"qId"`
	Data    struct {
		QrcID     string `json:"qrcId"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		Status    string `json:"status"`
		TrxID     string `json:"trxId"`
		OrderID   string `json:"orderId"`
		RequestID string `json:"requestId"`
		Kzo       string `json:"kzo"`
	} `json:"data"`
}

func (c *Client) SPBPaymentStatus(ctx context.Context, txID uuid.UUID, qrcID string) (entity.SPBPaymentStatus, error) {
	token, err := c.authToken(ctx)
	if err != nil {
		return "", fmt.Errorf("get auth token: %w", err)
	}

	reqData := SPBPaymentStatusRequest{
		QID:   txID,
		QRCID: qrcID,
	}

	b, err := json.Marshal(reqData)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	reqURL := c.cfg.BaseURL + "/outside/public/web/openapi/kib/spbc/b2bPartners/v1/one-time-qrc-status-v2"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IBM-Client-Id", c.cfg.ClientID) //nolint:canonicalheader
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.c.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad response status %d:\n%s", resp.StatusCode, body)
	}

	var respData SPBPaymentStatusResponse

	err = json.Unmarshal(body, &respData)
	if err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	return entity.SPBPaymentStatus(respData.Data.Status), nil
}

type authTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"` // In seconds
	TokenType   string `json:"token_type"`
}

func (c *Client) authToken(ctx context.Context) (string, error) {
	baseURL := "https://epa-ift.vtb.ru:443/passport/oauth2/token"

	form := make(url.Values)
	form.Add("grant_type", "client_credentials")
	form.Add("client_id", c.cfg.ClientID+"@ext.vtb.ru")
	form.Add("client_secret", c.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.c.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad response status %d:\n%s", resp.StatusCode, body)
	}

	var respData authTokenResponse

	err = json.Unmarshal(body, &respData)
	if err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	return respData.AccessToken, nil
}

type CreateCardPaymentRequest struct {
	Amount      int    `json:"amount"`
	Currency    int    `json:"currency"`
	UserName    string `json:"userName"`
	Password    string `json:"password"`
	ReturnURL   string `json:"returnUrl"`
	Description string `json:"description"`
	Language    string `json:"language"`
}

type CreateCardPaymentResponse struct {
	OrderID uuid.UUID `json:"orderId"`
	FormURL string    `json:"formUrl"`
}

func (c *Client) CreateCardPayment(ctx context.Context, txID uuid.UUID, amount decimal.Decimal, desc string) (entity.CardPayment, error) {
	reqURL := c.cfg.CardPaymentURL + "/payment/rest/register.do"

	form := make(url.Values)
	form.Set("amount", amount.Mul(decimal.NewFromInt(oneHundred)).String()) // In units
	form.Set("currency", "643")                                             // RUB
	form.Set("userName", c.cfg.CardPaymentLogin)
	form.Set("password", c.cfg.CardPaymentPassword)
	form.Set("returnUrl", c.cfg.CardRedirectURL)
	form.Set("description", desc)
	form.Set("orderNumber", txID.String())
	form.Set("language", "ru")

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.c.Do(req)
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return entity.CardPayment{}, fmt.Errorf("bad response status %d:\n%s", resp.StatusCode, body)
	}

	// Parse JSON response
	var data CreateCardPaymentResponse

	err = json.Unmarshal(body, &data)
	if err != nil {
		return entity.CardPayment{}, fmt.Errorf("unmarshal response: %w", err)
	}

	return entity.CardPayment{
		OrderID: data.OrderID,
		Link:    data.FormURL,
	}, nil
}

type CardPaymentStatusResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
	OrderNumber  string `json:"orderNumber"`
	OrderStatus  int    `json:"orderStatus"`
}

func (c *Client) CardPaymentStatus(ctx context.Context, txID uuid.UUID) (entity.CardPaymentStatus, error) {
	reqURL := c.cfg.CardPaymentURL + "/payment/rest/getOrderStatusExtended.do"

	form := make(url.Values)
	form.Set("userName", c.cfg.CardPaymentLogin)
	form.Set("password", c.cfg.CardPaymentPassword)
	form.Set("orderId", txID.String())
	form.Set("language", "ru")

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.c.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad response status %d:\n%s", resp.StatusCode, body)
	}

	// Parse JSON response
	var data CardPaymentStatusResponse

	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	return parsStatusToString(data.OrderStatus)
}

const (
	StatusCodeRegistered             = 0
	StatusCodeAuthorizedPending      = 1
	StatusCodeAuthorizedCompleted    = 2
	StatusCodeAuthorizationCancelled = 3
	StatusCodeRefunded               = 4
	StatusCodeACSInitiated           = 5
	StatusCodeAuthorizationDeclined  = 6
	StatusCodeWaitingPayment         = 7
	StatusCodeIntermediateCompleted  = 8
)

func parsStatusToString(status int) (entity.CardPaymentStatus, error) {
	switch status {
	case StatusCodeRegistered:
		return entity.CardPaymentStatusRegistered, nil
	case StatusCodeAuthorizedPending:
		return entity.CardPaymentStatusAuthorizedPending, nil
	case StatusCodeAuthorizedCompleted:
		return entity.CardPaymentStatusAuthorizedCompleted, nil
	case StatusCodeAuthorizationCancelled:
		return entity.CardPaymentStatusAuthorizationCancelled, nil
	case StatusCodeRefunded:
		return entity.CardPaymentStatusRefunded, nil
	case StatusCodeACSInitiated:
		return entity.CardPaymentStatusACSInitiated, nil
	case StatusCodeAuthorizationDeclined:
		return entity.CardPaymentStatusAuthorizationDeclined, nil
	case StatusCodeWaitingPayment:
		return entity.CardPaymentStatusWaitingPayment, nil
	case StatusCodeIntermediateCompleted:
		return entity.CardPaymentStatusIntermediateCompleted, nil
	default:
		return "", fmt.Errorf("unknown status code: %d", status)
	}
}
