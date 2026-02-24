package entity

import "time"

type UserTokens struct {
	IsFirstEnter    bool          `json:"firstEnter"`
	AccessToken     string        `json:"accessToken"`
	RefreshToken    string        `json:"refreshToken"`
	RefreshTokenTTL time.Duration `json:"-"`
}
