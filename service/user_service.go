package service

import (
	"authServer/model"
	"context"
	"errors"
)

var (
	ErrUserNotExist = errors.New("username is not exist")
	ErrPassword     = errors.New("invalid password")
)

// Service Define a service interface
type UserDetailsService interface {
	// Get UserDetails By username
	GetUserDetailByUsername(ctx context.Context, username, password string) (*model.UserDetails, error)
}

//UserService implement Service interface
type InMemoryUserDetailsService struct {
	userDetailsDict map[string]*model.UserDetails
}

func (service *InMemoryUserDetailsService) GetUserDetailByUsername(ctx context.Context, username, password string) (*model.UserDetails, error) {

	// 根據 username 獲取用戶訊息
	userDetails, ok := service.userDetailsDict[username]
	if ok {
		// 比較 password 是否正確
		if userDetails.Password == password {
			return userDetails, nil
		} else {
			return nil, ErrPassword
		}
	} else {
		return nil, ErrUserNotExist
	}

}

func NewInMemoryUserDetailsService(userDetailsList []*model.UserDetails) *InMemoryUserDetailsService {
	userDetailsDict := make(map[string]*model.UserDetails)

	if userDetailsList != nil {
		for _, value := range userDetailsList {
			userDetailsDict[value.Username] = value
		}
	}

	return &InMemoryUserDetailsService{
		userDetailsDict: userDetailsDict,
	}
}
