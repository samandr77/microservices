package roback

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/shopspring/decimal"
	"github.com/samandr77/microservices/documents/internal/entity"
)

type Roback struct {
	client    *http.Client
	url       string
	processID string
}

func NewClient(url string, processID string) *Roback {
	const timeout = time.Second * 5

	return &Roback{
		client: &http.Client{
			Timeout: timeout,
		},
		url:       url,
		processID: processID,
	}
}

type ReportRequest struct {
	DateSince    time.Time `json:"since"`
	DateUntil    time.Time `json:"until"`
	CampaignsIDs []int64   `json:"campaignIds"`
}

type (
	ReportResponse struct {
		Data ReportData `json:"data"`
	}

	ReportData struct {
		Since           time.Time         `json:"since"`
		Until           time.Time         `json:"until"`
		CampaignsSpends []CampaignsSpends `json:"campaignsSpends"`
	}

	CampaignsSpends struct {
		CampaignID int64 `json:"campaignId"`
		Spends     int64 `json:"spends"`
		StatusID   int   `json:"statusId"`
	}
)

func (c *Roback) GetBroadcastReport(
	ctx context.Context,
	campaignIDs []int64,
	dateFrom time.Time,
	dateTo time.Time,
) (entity.Report, error) {
	url := c.url + "/api/campaign/v1/reports/spends"

	jsonData, err := json.Marshal(ReportRequest{
		DateSince:    dateFrom,
		DateUntil:    dateTo,
		CampaignsIDs: campaignIDs,
	})
	if err != nil {
		return entity.Report{}, fmt.Errorf("marshal request in JSON: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return entity.Report{}, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Process-Id", c.processID)
	req.Header.Set("User-Agent", "Apidog/1.0.0")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return entity.Report{}, fmt.Errorf("send request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return entity.Report{}, fmt.Errorf("unexpected code %d", resp.StatusCode)
	}

	var data ReportResponse

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return entity.Report{}, fmt.Errorf("decode response: %w", err)
	}

	return reportFromAPI(data), nil
}

func reportFromAPI(report ReportResponse) entity.Report {
	return entity.Report{
		Since:           report.Data.Since,
		Until:           report.Data.Until,
		CampaignsSpends: campaignsSpendsFromAPI(report.Data.CampaignsSpends),
	}
}

func campaignsSpendsFromAPI(spends []CampaignsSpends) []entity.CampaignSpends {
	campaignsSpends := make([]entity.CampaignSpends, 0, len(spends))

	for _, cs := range spends {
		spend := entity.CampaignSpends{
			CampaignID: cs.CampaignID,
			Spends:     decimal.NewFromInt(cs.Spends).Div(decimal.New(100, 0)),
			StatusID:   cs.StatusID,
		}

		campaignsSpends = append(campaignsSpends, spend)
	}

	return campaignsSpends
}
