package transport

import (
	"authServer/endpoint"
	"authServer/service"
	"context"
	"errors"
	"log"
	"net/http"

	kithttp "github.com/go-kit/kit/transport/http"
)

var (
	ErrorBadRequest         = errors.New("invalid request parameter")
	ErrorGrantTypeRequest   = errors.New("invalid request grant type")
	ErrorTokenRequest       = errors.New("invalid request token")
	ErrInvalidClientRequest = errors.New("invalid client message")
)

// makeClientAuthorizationContext : 請求令牌前先驗證header中的客戶端信息
func makeClientAuthorizationContext(clientDetailsService service.ClientDetailsService, logger log.Logger) kithttp.RequestFunc {

	return func(ctx context.Context, r *http.Request) context.Context {
		// 獲取 header authorization中的客戶信息
		if clientId, clientSecret, ok := r.BasicAuth(); ok {
			// 驗證客戶端信息
			clientDetails, err := clientDetailsService.GetClientDetailByClientId(ctx, clientId, clientSecret)
			if err == nil {
				// 驗正成功 在請求上下文放入客戶端信息
				return context.WithValue(ctx, endpoint.OAuth2ClientDetailsKey, clientDetails)
			}
		}
		// 驗正失敗
		return context.WithValue(ctx, endpoint.OAuth2ErrorKey, ErrInvalidClientRequest)
	}
}
