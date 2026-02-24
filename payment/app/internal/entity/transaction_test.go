package entity_test

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/samandr77/microservices/payment/internal/entity"
)

func TestTransaction_TaxAmount(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name          string
		amount        float64
		taxPercent    uint32
		wantTaxAmount float64
	}{
		{
			name:          "small amount 0%",
			taxPercent:    0,
			amount:        0.40,
			wantTaxAmount: 0,
		},
		{
			name:          "small amount 20%",
			taxPercent:    20,
			amount:        0.40,
			wantTaxAmount: 0.08,
		},
		{
			name:          "small amount 10%",
			taxPercent:    10,
			amount:        0.40,
			wantTaxAmount: 0.04,
		},
		{
			name:          "medium amount",
			taxPercent:    20,
			amount:        1524.20,
			wantTaxAmount: 304.84,
		},
		{
			name:          "big amount",
			amount:        1_000_000_000.99,
			taxPercent:    20,
			wantTaxAmount: 200_000_000.20,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := entity.Transaction{
				Amount:         decimal.NewFromFloat(tt.amount),
				TaxRatePercent: tt.taxPercent,
			}

			gotTaxAmount := tr.TaxAmount()
			if gotTaxAmount.InexactFloat64() != tt.wantTaxAmount {
				t.Errorf("TaxAmount() = %v, want %v", gotTaxAmount, tt.wantTaxAmount)
			}
		})
	}
}
