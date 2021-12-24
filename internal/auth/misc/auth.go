package misc

import (
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/webdav-server/internal/auth"
	"github.com/mylxsw/webdav-server/internal/auth/ldap"
	"github.com/mylxsw/webdav-server/internal/auth/local"
)

type Auth struct {
	logger    log.Logger
	ldapAuth  auth.Auth
	localAuth auth.Auth
}

func New(ldapConf *ldap.Config, localConf *local.Config) auth.Auth {
	return &Auth{logger: log.Module("auth:none"), ldapAuth: ldap.New(ldapConf), localAuth: local.New(localConf)}
}

func (provider *Auth) GetUser(username string) (*auth.AuthedUser, error) {
	rs, err := provider.localAuth.GetUser(username)
	if err != nil {
		return provider.ldapAuth.GetUser(username)
	}

	return rs, nil
}

func (provider *Auth) Login(username, password string) (*auth.AuthedUser, error) {
	rs, err := provider.localAuth.Login(username, password)
	if err != nil {
		return provider.ldapAuth.Login(username, password)
	}

	return rs, nil
}

func (provider *Auth) Users() ([]auth.AuthedUser, error) {
	localUsers, _ := provider.localAuth.Users()
	ldapUsers, _ := provider.ldapAuth.Users()

	localUsers = append(localUsers, ldapUsers...)
	return localUsers, nil
}
