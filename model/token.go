package model

import "time"

type OAuth2Token struct {
	RefreshToken *OAuth2Token
	TokenType    string
	TokenValue   string
	ExpiresTime  *time.Time
}

func (oauth2Token *OAuth2Token) IsExpired() bool {
	return oauth2Token.ExpiresTime != nil &&
		oauth2Token.ExpiresTime.Before(time.Now())
}

type OAuth2Details struct {
	Client *ClientDetails
	User   *UserDetails
}
