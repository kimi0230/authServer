package model

type UserDetails struct {
	UserId      int64
	Username    string
	Password    string
	Authorities []string
}
