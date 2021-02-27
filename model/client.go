package model

type ClientDetails struct {
	// client id
	ClientId string
	// client key
	ClientSecret string
	// token 時效，秒
	AccessTokenValiditySeconds int
	// 刷新 token 有效時間，秒
	RefreshTokenValiditySeconds int
	// 導向 uri
	RegisteredRedirectUri string
	// 可以使用的授權類型
	AuthorizedGrantTypes []string
}
