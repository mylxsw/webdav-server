package service

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mylxsw/webdav-server/internal/auth"
	"github.com/mylxsw/webdav-server/internal/cache"
)

type AuthService interface {
	Login(username, password string) (*auth.AuthedUser, error)
}

type authService struct {
	author auth.Author
	cache  cache.Driver
}

func NewAuthService(author auth.Author, cache cache.Driver) AuthService {
	return &authService{author: author, cache: cache}
}

func (srv *authService) Login(username, password string) (*auth.AuthedUser, error) {
	cacheKey := fmt.Sprintf("webdav:login:%s:%s", username, fmt.Sprintf("%x", md5.Sum([]byte(password+"-webdav.server"))))
	cachedRaw, err := srv.cache.Get(cacheKey)
	if err == nil {
		var authedUser auth.AuthedUser
		if err := json.Unmarshal([]byte(cachedRaw), &authedUser); err != nil {
			return nil, err
		}

		return &authedUser, nil
	}

	authedUser, err := srv.author.Login(username, password)
	if err != nil {
		return nil, err
	}

	authedUserRaw, err := json.Marshal(authedUser)
	if err != nil {
		return nil, err
	}

	if err := srv.cache.Set(cacheKey, string(authedUserRaw), 15*time.Minute); err != nil {
		return nil, err
	}

	return authedUser, nil
}
