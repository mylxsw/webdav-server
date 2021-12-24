package local

import (
	"encoding/base64"

	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/webdav-server/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	logger log.Logger
	conf   *Config
	users  map[string]User
}

func New(conf *Config) auth.Auth {
	users := make(map[string]User)
	for _, user := range conf.Users {
		users[user.Username] = user
	}

	return &Auth{logger: log.Module("auth:local"), conf: conf, users: users}
}

func (provider *Auth) GetUser(username string) (*auth.AuthedUser, error) {
	if user, ok := provider.users[username]; ok {
		return &auth.AuthedUser{
			Account: user.Username,
		}, nil
	}

	return nil, auth.ErrNoSuchUser
}

func (provider *Auth) Login(username, password string) (*auth.AuthedUser, error) {

	if user, ok := provider.users[username]; ok {
		switch user.Algo {
		case "base64":
			savedPassword, err := base64.StdEncoding.DecodeString(user.Password)
			if err != nil {
				return nil, auth.ErrInvalidPassword
			}
			if string(savedPassword) != password {
				return nil, auth.ErrInvalidPassword
			}
		case "bcrypt":
			if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
				return nil, auth.ErrInvalidPassword
			}
		default:
			if user.Password != password {
				return nil, auth.ErrInvalidPassword
			}
		}

		return &auth.AuthedUser{
			Account: user.Username,
		}, nil
	}

	return nil, auth.ErrNoSuchUser
}

func (provider *Auth) Users() ([]auth.AuthedUser, error) {
	users := make([]auth.AuthedUser, 0)
	for _, u := range provider.users {
		users = append(users, auth.AuthedUser{Account: u.Username})
	}

	return users, nil
}

type User struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	Algo     string `json:"algo" yaml:"algo"`
}

type Config struct {
	Users []User `json:"users" yaml:"users"`
}
