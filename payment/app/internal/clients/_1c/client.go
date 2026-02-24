package _1c

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
	"github.com/shopspring/decimal"
)

type Client struct {
	baseURL string
	http    *http.Client
}

type CreateBillRequest struct {
	Guid         uuid.UUID        `json:"guid"`       // Client identifier.
	BillNumber   int64            `json:"billNumber"` // Globally unique bill identifier.
	BillDate     time.Time        `json:"billDate"`
	BillType     string           `json:"billType"`
	ServicesList []ServiceRequest `json:"servicesList"`
}

type ServiceRequest struct {
	Name        string          `json:"name"`        // "Пополнение баланса"
	TaxRate     string          `json:"taxRate"`     // 20% for example.
	TaxAmount   decimal.Decimal `json:"taxAmount"`   // 40.08 two decimal places.
	TotalAmount decimal.Decimal `json:"totalAmount"` // 200.40 two decimal places.
}

type CreateBillResponse struct {
	Recipient struct {
		Name        string `json:"name"`
		Inn         string `json:"inn"`
		Kpp         string `json:"kpp"`
		Address     string `json:"address"`
		BankDetails struct {
			Bic                  string `json:"bic"`
			CorrespondentAccount string `json:"correspondentAccount"`
			AccountNumber        string `json:"accountNumber"`
			Name                 string `json:"name"`
			Ogrn                 string `json:"ogrn"`
			Oktmo                string `json:"oktmo"`
			Okved                string `json:"okved"`
		} `json:"bankDetails"`
	} `json:"recipient"`
}

func (c *Client) CreateBill(ctx context.Context, tx entity.Transaction) (entity.ClientRequisites, error) {
	reqData := CreateBillRequest{
		Guid:       tx.ClientGUID,
		BillNumber: tx.Number,
		BillDate:   tx.CreatedAt,
		BillType:   billTypeToAPI(tx.PaymentMethod),
		ServicesList: []ServiceRequest{
			{
				Name:        "Пополнение баланса",
				TaxRate:     fmt.Sprintf("%d%%", tx.TaxRatePercent),
				TaxAmount:   tx.TaxAmount(),
				TotalAmount: tx.Amount,
			},
		},
	}

	b, err := json.Marshal(reqData)
	if err != nil {
		return entity.ClientRequisites{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/bill", bytes.NewReader(b))
	if err != nil {
		return entity.ClientRequisites{}, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return entity.ClientRequisites{}, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return entity.ClientRequisites{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return entity.ClientRequisites{}, fmt.Errorf("unexpected status code: %d\n%s", resp.StatusCode, body)
	}

	var res CreateBillResponse

	err = json.Unmarshal(body, &res)
	if err != nil {
		return entity.ClientRequisites{}, fmt.Errorf("decode response: %w", err)
	}

	return entity.ClientRequisites{
		Name:                     res.Recipient.Name,
		INN:                      res.Recipient.Inn,
		KPP:                      res.Recipient.Kpp,
		Address:                  res.Recipient.Address,
		BankBic:                  res.Recipient.BankDetails.Bic,
		BankCorrespondentAccount: res.Recipient.BankDetails.CorrespondentAccount,
		BankAccountNumber:        res.Recipient.BankDetails.AccountNumber,
		BankName:                 res.Recipient.BankDetails.Name,
	}, nil
}

func NewClient(baseURL string) *Client {
	timeout := time.Second * 10

	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout:   timeout,
			Transport: transport.NewJWTRoundTripper(http.DefaultTransport),
		},
	}
}

func billTypeToAPI(billType entity.PaymentMethod) string {
	switch billType {
	case entity.PaymentMethodCard:
		return "card"
	case entity.PaymentMethodSBP:
		return "sbp"
	case entity.PaymentMethodInvoice:
		return "invoice"
	default:
		return ""
	}
}
