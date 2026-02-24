package onec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/samandr77/microservices/documents/internal/entity"
)

type OneC struct {
	client *http.Client
	url    string
}

func NewClient(url string) *OneC {
	const timeout = time.Second * 5

	return &OneC{
		client: &http.Client{
			Timeout: timeout,
		},
		url: url,
	}
}

type GenerateDocumentsRequest struct {
	GUID         uuid.UUID `json:"guid"`
	DateSince    time.Time `json:"dateSince"`
	DateUntil    time.Time `json:"dateUntil"`
	ServicesList []Service `json:"servicesList"`
}

type Service struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	TaxRate     string          `json:"taxRate"`
	TaxAmount   decimal.Decimal `json:"taxAmount"`
	TotalAmount decimal.Decimal `json:"totalAmount"`
}

type GenerateDocumentsResponse struct {
	ID   string `json:"id"`
	Date string `json:"date"`
}

func (c *OneC) GenerateDocuments(ctx context.Context, report entity.Report, guid uuid.UUID, campaignsInfo []entity.CampaignInfo) error {
	jsonData, err := json.Marshal(newGenerateDocumentsRequest(report, guid, campaignsInfo))
	if err != nil {
		return fmt.Errorf("marshal body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/act", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return err
	}

	var data GenerateDocumentsResponse

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func newGenerateDocumentsRequest(report entity.Report, guid uuid.UUID, campaignsInfo []entity.CampaignInfo) GenerateDocumentsRequest {
	campMap := make(map[int64]string, len(campaignsInfo))

	for _, v := range campaignsInfo {
		campMap[v.CampaignID] = v.CampaignName
	}

	servicesList := make([]Service, 0, len(report.CampaignsSpends))

	for _, v := range report.CampaignsSpends {
		taxAmount := v.Spends.Mul(decimal.New(20, 0)).Div(decimal.New(120, 0))

		service := Service{
			Name:        fmt.Sprintf("Рекламная кампания %s в Русс.директ с %v по %v", campMap[v.CampaignID], report.Since, report.Until),
			Type:        "",
			TaxRate:     "20%",
			TaxAmount:   taxAmount,
			TotalAmount: v.Spends,
		}

		servicesList = append(servicesList, service)
	}

	return GenerateDocumentsRequest{
		GUID:         guid,
		DateSince:    report.Since,
		DateUntil:    report.Until,
		ServicesList: servicesList,
	}
}
