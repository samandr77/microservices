package roback

import (
	"context"
	"time"

	"github.com/shopspring/decimal"
	"github.com/samandr77/microservices/documents/internal/entity"
)

type Mock struct{}

func NewMock() *Mock {
	return &Mock{}
}

func (c *Mock) GetBroadcastReport(
	_ context.Context,
	campaignIDs []int64,
	dateFrom time.Time,
	dateTo time.Time,
) (entity.Report, error) {
	spends := make([]entity.CampaignSpends, 0, len(campaignIDs))

	for _, v := range campaignIDs {
		s := entity.CampaignSpends{
			CampaignID: v,
			Spends:     decimal.RequireFromString("6601100.0"),
			StatusID:   5,
		}

		spends = append(spends, s)
	}

	return entity.Report{
		Since:           dateFrom,
		Until:           dateTo,
		CampaignsSpends: spends,
	}, nil
}
