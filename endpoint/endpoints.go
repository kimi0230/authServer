package endpoint

import (
	"authServer/model"
	"authServer/service"
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/go-kit/kit/endpoint"
)

// CalculateEndpoint define endpoint
type OAuth2Endpoints struct {
	TokenEndpoint       endpoint.Endpoint
	CheckTokenEndpoint  endpoint.Endpoint
	HealthCheckEndpoint endpoint.Endpoint
	SimpleEndpoint      endpoint.Endpoint
	AdminEndpoint       endpoint.Endpoint
}

const (
	OAuth2DetailsKey       = "OAuth2Details"
	OAuth2ClientDetailsKey = "OAuth2ClientDetails"
	OAuth2ErrorKey         = "OAuth2Error"
)

var (
	ErrInvalidClientRequest = errors.New("invalid client message")
	ErrInvalidUserRequest   = errors.New("invalid user message")
	ErrNotPermit            = errors.New("not permit")
)

type TokenRequest struct {
	GrantType string
	Reader    *http.Request
}

type TokenResponse struct {
	AccessToken *model.OAuth2Token `json:"access_token"`
	Error       string             `json:"error"`
}

// MakeClientAuthorizationMiddleware : 中間層, 驗證請求上下文是否攜帶客戶端信息
func MakeClientAuthorizationMiddleware(logger log.Logger) endpoint.Middleware {
	// Endpoint is the fundamental building block of servers and clients.
	// It represents a single RPC method.
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {

			// 請求上下文是否存在錯誤
			if err, ok := ctx.Value(OAuth2ErrorKey).(error); ok {
				return nil, err
			}

			// 驗證客戶端信息是否存在
			if _, ok := ctx.Value(OAuth2ClientDetailsKey).(*model.ClientDetails); !ok {
				return nil, ErrInvalidClientRequest
			}
			return next(ctx, request)
		}
	}
}

// MakeTokenEndpoint : 將context終獲取到的客戶端信息, 委託TokenGrant 根據授權類型和用戶憑證為客戶端生成token
func MakeTokenEndpoint(svc service.TokenGranter, clientService service.ClientDetailsService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(*TokenRequest)
		token, err := svc.Grant(ctx, req.GrantType, ctx.Value(OAuth2ClientDetailsKey).(*model.ClientDetails), req.Reader)
		var errString = ""
		if err != nil {
			errString = err.Error()
		}

		return TokenResponse{
			AccessToken: token,
			Error:       errString,
		}, nil
	}
}
