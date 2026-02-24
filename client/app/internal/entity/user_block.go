package entity

import (
	"time"

	"github.com/gofrs/uuid/v5"
)

type BlockType string

const (
	BlockTypePermanent BlockType = "0"
	BlockTypeTemporary BlockType = "1"
)

type UserBlock struct {
	ID                     uuid.UUID  `json:"id"`
	UserID                 uuid.UUID  `json:"user_id"`
	BlockedTo              *time.Time `json:"blocked_to,omitempty"`
	BlockType              *BlockType `json:"block_type,omitempty"`
	BlocksByPeriod         int        `json:"blocks_by_period"`
	FirstBlockDateByPeriod *time.Time `json:"first_block_date_by_period,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

func (ub *UserBlock) IsTemporary() bool {
	if ub.BlockType == nil {
		return false
	}

	return *ub.BlockType == BlockTypeTemporary
}

func (ub *UserBlock) IsExpired() bool {
	if !ub.IsTemporary() || ub.BlockedTo == nil {
		return false
	}

	return time.Now().After(*ub.BlockedTo)
}

func (ub *UserBlock) ShouldResetCounter(blockPeriodHours int) bool {
	if ub.FirstBlockDateByPeriod == nil {
		return false
	}

	blockPeriodDuration := time.Duration(blockPeriodHours) * time.Hour

	return time.Since(*ub.FirstBlockDateByPeriod) >= blockPeriodDuration
}
