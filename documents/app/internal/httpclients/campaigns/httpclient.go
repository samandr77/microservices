package campaigns

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

type Campaigns struct {
	client *http.Client
	url    string
}

func NewClient(url string) *Campaigns {
	const timeout = time.Second * 5

	return &Campaigns{
		client: &http.Client{
			Timeout: timeout,
		},
		url: url,
	}
}

type GetCampaignsRequest struct {
	ClientID string    `json:"clientID"`
	DateFrom time.Time `json:"dateFrom"`
	DateTo   time.Time `json:"dateTo"`
}

type GetCampaignsResponse struct {
	CampaignsInfo []CampaignInfo
}

type CampaignInfo struct {
	CampaignID   int64  `json:"campaignsId"`
	CampaignName string `json:"campaignName"`
}

func (c *Campaigns) GetCampaigns(
	ctx context.Context,
	clientID uuid.UUID,
	startDate time.Time,
	endDate time.Time,
) ([]entity.CampaignInfo, error) {
	url := c.url + "/api/documents/campaigns"

	body := GetCampaignsRequest{
		ClientID: clientID.String(),
		DateFrom: startDate,
		DateTo:   endDate,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil,
			fmt.Errorf("%w: campaigns to client ID %s not found: status %d", entity.ErrNotFound, clientID, resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected code %d", resp.StatusCode)
	}

	var campaignsInfo GetCampaignsResponse

	err = json.NewDecoder(resp.Body).Decode(&campaignsInfo)
	if err != nil {
		return nil, err
	}

	return campaignsFromAPI(campaignsInfo), nil
}

func campaignsFromAPI(campaigns GetCampaignsResponse) []entity.CampaignInfo {
	resp := make([]entity.CampaignInfo, 0, len(campaigns.CampaignsInfo))

	for _, v := range campaigns.CampaignsInfo {
		camp := entity.CampaignInfo{
			CampaignID:   v.CampaignID,
			CampaignName: v.CampaignName,
		}

		resp = append(resp, camp)
	}

	return resp
}

type (
	ActualCampaignInfoRequest struct {
		Campaigns []Campaign `json:"campaign"`
	}

	Campaign struct {
		CampaignID     int64 `json:"campaignId"`
		CampaignStatus int   `json:"status"`
	}
)

func (c *Campaigns) ActualCampaignInfo(ctx context.Context, info entity.Report) error {
	url := c.url + "api/campaigns/actualInfo"

	data, err := json.Marshal(campaignsInfoToAPI(info))
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	token, err := entity.TokenFromContext(ctx)
	if err != nil {
		return fmt.Errorf("get token from ctx: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected code %d", resp.StatusCode)
	}

	return nil
}

func campaignsInfoToAPI(info entity.Report) ActualCampaignInfoRequest {
	campaigns := make([]Campaign, 0, len(info.CampaignsSpends))

	for _, v := range info.CampaignsSpends {
		c := Campaign{
			CampaignID:     v.CampaignID,
			CampaignStatus: v.StatusID,
		}

		campaigns = append(campaigns, c)
	}

	return ActualCampaignInfoRequest{
		Campaigns: campaigns,
	}
}
