package service

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mylxsw/webdav-server/internal/auth"
	"github.com/mylxsw/webdav-server/internal/cache"
)

type AuthService interface {
	Login(username, password string) (*auth.AuthedUser, error)
	GetUser(username string) (*auth.AuthedUser, error)
}

type authService struct {
	auth  auth.Auth
	cache cache.Cache
}

func NewAuthService(auth auth.Auth, cache cache.Cache) AuthService {
	return &authService{auth: auth, cache: cache}
}

func (srv *authService) Login(username, password string) (*auth.AuthedUser, error) {
	cacheKey := fmt.Sprintf("webdav:login:%s:%s", username, password)
	cachedRaw, err := srv.cache.Get(cacheKey)
	if err == nil {
		var authedUser auth.AuthedUser
		if err := json.Unmarshal([]byte(cachedRaw), &authedUser); err != nil {
			return nil, err
		}

		return &authedUser, nil
	}

	authedUser, err := srv.auth.Login(username, password)
	if err != nil {
		return nil, err
	}

	authedUserRaw, err := json.Marshal(authedUser)
	if err != nil {
		return nil, err
	}

	if err := srv.cache.Set(cacheKey, string(authedUserRaw), 5*time.Minute); err != nil {
		return nil, err
	}

	return authedUser, nil
}

func (srv *authService) GetUser(username string) (*auth.AuthedUser, error) {
	cacheKey := fmt.Sprintf("webdav:user:%s", username)
	cachedRaw, err := srv.cache.Get(cacheKey)
	if err != nil {
		var authedUser auth.AuthedUser
		if err := json.Unmarshal([]byte(cachedRaw), &authedUser); err != nil {
			return nil, err
		}

		return &authedUser, nil
	}

	authedUser, err := srv.auth.GetUser(username)
	if err != nil {
		return nil, err
	}

	authedUserRaw, err := json.Marshal(authedUser)
	if err != nil {
		return nil, err
	}

	if err := srv.cache.Set(cacheKey, string(authedUserRaw), 5*time.Minute); err != nil {
		return nil, err
	}

	return authedUser, nil
}
