package service

import (
	. "authServer/model"
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	uuid "github.com/satori/go.uuid"
)

var (
	ErrNotSupportGrantType               = errors.New("grant type is not supported")
	ErrNotSupportOperation               = errors.New("no support operation")
	ErrInvalidUsernameAndPasswordRequest = errors.New("invalid username, password")
	ErrInvalidTokenRequest               = errors.New("invalid token")
	ErrExpiredToken                      = errors.New("token is expired")
)

// token grant 接口, 根據授權類型使用不同的方式對用戶和客戶驗證
type TokenGranter interface {
	Grant(ctx context.Context, grantType string, client *ClientDetails, reader *http.Request) (*OAuth2Token, error)
}

type ComposeTokenGranter struct {
	TokenGrantDict map[string]TokenGranter
}

func NewComposeTokenGranter(tokenGrantDict map[string]TokenGranter) TokenGranter {
	return &ComposeTokenGranter{
		TokenGrantDict: tokenGrantDict,
	}
}

// Grant : 根據grantType從map取出對應類型的tokengranter interface實現結構
func (tokenGranter *ComposeTokenGranter) Grant(ctx context.Context, grantType string, client *ClientDetails, reader *http.Request) (*OAuth2Token, error) {

	dispatchGranter := tokenGranter.TokenGrantDict[grantType]

	if dispatchGranter == nil {
		return nil, ErrNotSupportGrantType
	}

	return dispatchGranter.Grant(ctx, grantType, client, reader)
}

// Refresh Token
type RefreshTokenGranter struct {
	supportGrantType string
	tokenService     TokenService
}

func NewRefreshGranter(grantType string, userDetailsService UserDetailsService, tokenService TokenService) TokenGranter {
	return &RefreshTokenGranter{
		supportGrantType: grantType,
		tokenService:     tokenService,
	}
}

func (tokenGranter *RefreshTokenGranter) Grant(ctx context.Context, grantType string, client *ClientDetails, reader *http.Request) (*OAuth2Token, error) {
	if grantType != tokenGranter.supportGrantType {
		return nil, ErrNotSupportGrantType
	}
	// 取得refresh token
	refreshTokenValue := reader.URL.Query().Get("refresh_token")

	if refreshTokenValue == "" {
		return nil, ErrInvalidTokenRequest
	}

	return tokenGranter.tokenService.RefreshAccessToken(refreshTokenValue)

}

type TokenService interface {
	// 根據token 取得對應用戶和客戶訊息
	GetOAuth2DetailsByAccessToken(tokenValue string) (*OAuth2Details, error)
	// 根據用户信息和客户端信息生成 token
	CreateAccessToken(oauth2Details *OAuth2Details) (*OAuth2Token, error)
	// 刷新 token
	RefreshAccessToken(refreshTokenValue string) (*OAuth2Token, error)
	// 根據用户信息和客户端信息 取得token
	GetAccessToken(details *OAuth2Details) (*OAuth2Token, error)
	// 根據 token 取得 token 結構
	ReadAccessToken(tokenValue string) (*OAuth2Token, error)
}

type DefaultTokenService struct {
	tokenStore    TokenStore
	tokenEnhancer TokenEnhancer
}

// GetOAuth2DetailsByAccessToken : 根據token 取得對應用戶和客戶訊息
func (tokenService *DefaultTokenService) GetOAuth2DetailsByAccessToken(tokenValue string) (*OAuth2Details, error) {

	accessToken, err := tokenService.tokenStore.ReadAccessToken(tokenValue)
	if err == nil {
		if accessToken.IsExpired() {
			return nil, ErrExpiredToken
		}
		return tokenService.tokenStore.ReadOAuth2Details(tokenValue)
	}
	return nil, err
}

// CreateAccessToken : 根據用户信息和客户端信息生成 token
func (tokenService *DefaultTokenService) CreateAccessToken(oauth2Details *OAuth2Details) (*OAuth2Token, error) {
	existToken, err := tokenService.tokenStore.GetAccessToken(oauth2Details)
	var refreshToken *OAuth2Token
	if err == nil {
		// token未過期 直接返回
		if !existToken.IsExpired() {
			tokenService.tokenStore.StoreAccessToken(existToken, oauth2Details)
			return existToken, nil
		}
		// token已失效，移除
		tokenService.tokenStore.RemoveAccessToken(existToken.TokenValue)
		if existToken.RefreshToken != nil {
			refreshToken = existToken.RefreshToken
			tokenService.tokenStore.RemoveRefreshToken(refreshToken.TokenType)
		}
	}

	if refreshToken == nil || refreshToken.IsExpired() {
		refreshToken, err = tokenService.createRefreshToken(oauth2Details)
		if err != nil {
			return nil, err
		}
	}

	// 生成新的token
	accessToken, err := tokenService.createAccessToken(refreshToken, oauth2Details)
	if err == nil {
		// 保存新生成令牌
		tokenService.tokenStore.StoreAccessToken(accessToken, oauth2Details)
		tokenService.tokenStore.StoreRefreshToken(refreshToken, oauth2Details)
	}
	return accessToken, err
}

func (tokenService *DefaultTokenService) createAccessToken(refreshToken *OAuth2Token, oauth2Details *OAuth2Details) (*OAuth2Token, error) {

	validitySeconds := oauth2Details.Client.AccessTokenValiditySeconds
	s, _ := time.ParseDuration(strconv.Itoa(validitySeconds) + "s")
	expiredTime := time.Now().Add(s)
	u, _ := uuid.NewV4()
	accessToken := &OAuth2Token{
		RefreshToken: refreshToken,
		ExpiresTime:  &expiredTime,
		TokenValue:   u.String(),
	}

	if tokenService.tokenEnhancer != nil {
		return tokenService.tokenEnhancer.Enhance(accessToken, oauth2Details)
	}
	return accessToken, nil
}

// RefreshAccessToken : 刷新 token
func (tokenService *DefaultTokenService) RefreshAccessToken(refreshTokenValue string) (*OAuth2Token, error) {

	refreshToken, err := tokenService.tokenStore.ReadRefreshToken(refreshTokenValue)
	if err == nil {
		if refreshToken.IsExpired() {
			return nil, ErrExpiredToken
		}
		oauth2Details, err := tokenService.tokenStore.ReadOAuth2DetailsForRefreshToken(refreshTokenValue)
		if err == nil {
			oauth2Token, err := tokenService.tokenStore.GetAccessToken(oauth2Details)
			// 移除原有的token
			if err == nil {
				tokenService.tokenStore.RemoveAccessToken(oauth2Token.TokenValue)
			}

			// 移除已使用的refresh token
			tokenService.tokenStore.RemoveRefreshToken(refreshTokenValue)
			refreshToken, err = tokenService.createRefreshToken(oauth2Details)
			if err == nil {
				accessToken, err := tokenService.createAccessToken(refreshToken, oauth2Details)
				if err == nil {
					tokenService.tokenStore.StoreAccessToken(accessToken, oauth2Details)
					tokenService.tokenStore.StoreRefreshToken(refreshToken, oauth2Details)
				}
				return accessToken, err
			}
		}
	}
	return nil, err
}

// GetAccessToken : 根據用户信息和客户端信息 取得token
func (tokenService *DefaultTokenService) GetAccessToken(details *OAuth2Details) (*OAuth2Token, error) {
	return tokenService.tokenStore.GetAccessToken(details)
}

// ReadAccessToken : 根據 token 取得 token 結構
func (tokenService *DefaultTokenService) ReadAccessToken(tokenValue string) (*OAuth2Token, error) {
	return tokenService.tokenStore.ReadAccessToken(tokenValue)
}

func NewTokenService(tokenStore TokenStore, tokenEnhancer TokenEnhancer) TokenService {
	return &DefaultTokenService{
		tokenStore:    tokenStore,
		tokenEnhancer: tokenEnhancer,
	}
}

func (tokenService *DefaultTokenService) createRefreshToken(oauth2Details *OAuth2Details) (*OAuth2Token, error) {
	validitySeconds := oauth2Details.Client.RefreshTokenValiditySeconds
	s, _ := time.ParseDuration(strconv.Itoa(validitySeconds) + "s")
	expiredTime := time.Now().Add(s)
	u, _ := uuid.NewV4()
	refreshToken := &OAuth2Token{
		ExpiresTime: &expiredTime,
		TokenValue:  u.String(),
	}

	if tokenService.tokenEnhancer != nil {
		return tokenService.tokenEnhancer.Enhance(refreshToken, oauth2Details)
	}
	return refreshToken, nil
}

//  令牌儲存器, 負責生成/維護 token, 用戶,客戶之間的綁定關係
// 通過jwt來實現
type TokenStore interface {
	// 儲存 Token
	StoreAccessToken(oauth2Token *OAuth2Token, oauth2Details *OAuth2Details)
	// 根據 token 取得 token 結構
	ReadAccessToken(tokenValue string) (*OAuth2Token, error)
	// 根據 token 取得 客户端和用户信息
	ReadOAuth2Details(tokenValue string) (*OAuth2Details, error)
	// 根據用户信息和客户端信息 取得token
	GetAccessToken(oauth2Details *OAuth2Details) (*OAuth2Token, error)
	// 移除 Token
	RemoveAccessToken(tokenValue string)
	// 儲存 refresh token
	StoreRefreshToken(oauth2Token *OAuth2Token, oauth2Details *OAuth2Details)
	// 移除 refresh token
	RemoveRefreshToken(oauth2Token string)
	// 用 token 取得 refresh token
	ReadRefreshToken(tokenValue string) (*OAuth2Token, error)
	// 根據token 取得 refresh token 對應的客户端和用户信息
	ReadOAuth2DetailsForRefreshToken(tokenValue string) (*OAuth2Details, error)
}

type JwtTokenStore struct {
	jwtTokenEnhancer *JwtTokenEnhancer
}

func NewJwtTokenStore(jwtTokenEnhancer *JwtTokenEnhancer) TokenStore {
	return &JwtTokenStore{
		jwtTokenEnhancer: jwtTokenEnhancer,
	}
}

func (tokenStore *JwtTokenStore) StoreAccessToken(oauth2Token *OAuth2Token, oauth2Details *OAuth2Details) {

}

func (tokenStore *JwtTokenStore) ReadAccessToken(tokenValue string) (*OAuth2Token, error) {
	oauth2Token, _, err := tokenStore.jwtTokenEnhancer.Extract(tokenValue)
	return oauth2Token, err
}

// 根據 token 取得 客户端和用户信息
func (tokenStore *JwtTokenStore) ReadOAuth2Details(tokenValue string) (*OAuth2Details, error) {
	_, oauth2Details, err := tokenStore.jwtTokenEnhancer.Extract(tokenValue)
	return oauth2Details, err
}

// 根據用户信息和客户端信息 取得token
func (tokenStore *JwtTokenStore) GetAccessToken(oauth2Details *OAuth2Details) (*OAuth2Token, error) {
	return nil, ErrNotSupportOperation
}

// 移除 Token
func (tokenStore *JwtTokenStore) RemoveAccessToken(tokenValue string) {

}

// 儲存 refresh token
func (tokenStore *JwtTokenStore) StoreRefreshToken(oauth2Token *OAuth2Token, oauth2Details *OAuth2Details) {

}

// 移除 refresh token
func (tokenStore *JwtTokenStore) RemoveRefreshToken(oauth2Token string) {

}

// 用 token 取得 refresh token
func (tokenStore *JwtTokenStore) ReadRefreshToken(tokenValue string) (*OAuth2Token, error) {
	oauth2Token, _, err := tokenStore.jwtTokenEnhancer.Extract(tokenValue)
	return oauth2Token, err
}

// 根據token 取得 refresh token 對應的客户端和用户信息
func (tokenStore *JwtTokenStore) ReadOAuth2DetailsForRefreshToken(tokenValue string) (*OAuth2Details, error) {
	_, oauth2Details, err := tokenStore.jwtTokenEnhancer.Extract(tokenValue)
	return oauth2Details, err
}

type TokenEnhancer interface {
	// 組裝 Token 訊息
	Enhance(oauth2Token *OAuth2Token, oauth2Details *OAuth2Details) (*OAuth2Token, error)
	// 從 Token 中還原訊息
	Extract(tokenValue string) (*OAuth2Token, *OAuth2Details, error)
}

type OAuth2TokenCustomClaims struct {
	UserDetails   UserDetails
	ClientDetails ClientDetails
	RefreshToken  OAuth2Token
	jwt.StandardClaims
}

type JwtTokenEnhancer struct {
	secretKey []byte
}

func (enhancer *JwtTokenEnhancer) sign(oauth2Token *OAuth2Token, oauth2Details *OAuth2Details) (*OAuth2Token, error) {

	expireTime := oauth2Token.ExpiresTime
	clientDetails := *oauth2Details.Client
	userDetails := *oauth2Details.User
	// 去除敏感訊息
	clientDetails.ClientSecret = ""
	userDetails.Password = ""

	// 將用戶和客戶訊息寫到JWT的聲明中
	claims := OAuth2TokenCustomClaims{
		UserDetails:   userDetails,
		ClientDetails: clientDetails,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
			Issuer:    "System",
		},
	}

	if oauth2Token.RefreshToken != nil {
		claims.RefreshToken = *oauth2Token.RefreshToken
	}

	// 使用key 對 JWT 進行簽名
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 放回轉換後的token
	tokenValue, err := token.SignedString(enhancer.secretKey)

	if err == nil {
		oauth2Token.TokenValue = tokenValue
		oauth2Token.TokenType = "jwt"
		return oauth2Token, nil

	}
	return nil, err
}

func NewJwtTokenEnhancer(secretKey string) TokenEnhancer {
	return &JwtTokenEnhancer{
		secretKey: []byte(secretKey),
	}
}

func (enhancer *JwtTokenEnhancer) Enhance(oauth2Token *OAuth2Token, oauth2Details *OAuth2Details) (*OAuth2Token, error) {
	return enhancer.sign(oauth2Token, oauth2Details)
}

func (enhancer *JwtTokenEnhancer) Extract(tokenValue string) (*OAuth2Token, *OAuth2Details, error) {

	token, err := jwt.ParseWithClaims(tokenValue, &OAuth2TokenCustomClaims{}, func(token *jwt.Token) (i interface{}, e error) {
		return enhancer.secretKey, nil
	})

	if err == nil {

		claims := token.Claims.(*OAuth2TokenCustomClaims)
		expiresTime := time.Unix(claims.ExpiresAt, 0)

		return &OAuth2Token{
				RefreshToken: &claims.RefreshToken,
				TokenValue:   tokenValue,
				ExpiresTime:  &expiresTime,
			}, &OAuth2Details{
				User:   &claims.UserDetails,
				Client: &claims.ClientDetails,
			}, nil

	}
	return nil, nil, err
}
