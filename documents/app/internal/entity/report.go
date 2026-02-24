package entity

import (
	"time"

	"github.com/shopspring/decimal"
)

type (
	Report struct {
		Since           time.Time
		Until           time.Time
		CampaignsSpends []CampaignSpends
	}

	CampaignSpends struct {
		CampaignID int64
		Spends     decimal.Decimal
		StatusID   int
	}
)
