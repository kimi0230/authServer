package service

import (
	"authServer/model"
	"context"
	"errors"
)

var (
	ErrClientNotExist = errors.New("clientId is not exist")
	ErrClientSecret   = errors.New("invalid clientSecret")
)

// Service Define a service interface
// ClientDetailsService : 根據client id 加載並驗證用戶訊息
type ClientDetailsService interface {
	GetClientDetailByClientId(ctx context.Context, clientId string, clientSecret string) (*model.ClientDetails, error)
}

// InMemoryClientDetailsService : client id 字典對應個別資料
type InMemoryClientDetailsService struct {
	clientDetailsDict map[string]*model.ClientDetails
}

// NewInMemoryClientDetailService : 模擬用戶訊息存在內存
func NewInMemoryClientDetailService(clientDetailsList []*model.ClientDetails) *InMemoryClientDetailsService {
	clientDetailsDict := make(map[string]*model.ClientDetails)

	if clientDetailsList != nil {
		for _, value := range clientDetailsList {
			clientDetailsDict[value.ClientId] = value
		}
	}

	return &InMemoryClientDetailsService{
		clientDetailsDict: clientDetailsDict,
	}
}

// GetClientDetailByClientId : 實現interface
func (service *InMemoryClientDetailsService) GetClientDetailByClientId(ctx context.Context, clientId string, clientSecret string) (*model.ClientDetails, error) {

	// 根據 clientId 取得 clientDetails
	clientDetails, ok := service.clientDetailsDict[clientId]
	if ok {
		// 比較 clientSecret 是否正確
		if clientDetails.ClientSecret == clientSecret {
			return clientDetails, nil
		} else {
			return nil, ErrClientSecret
		}
	} else {
		return nil, ErrClientNotExist
	}
}
