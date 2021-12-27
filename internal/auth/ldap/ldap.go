package ldap

import (
	"errors"
	"fmt"
	"time"

	lp "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/webdav-server/internal/auth"
)

type Config struct {
	URL         string `json:"url,omitempty" yaml:"url,omitempty"`
	BaseDN      string `json:"base_dn,omitempty" yaml:"base_dn,omitempty"`
	Username    string `json:"username,omitempty" yaml:"username,omitempty"`
	Password    string `json:"-" yaml:"password"`
	DisplayName string `json:"display_name,omitempty" yaml:"display_name,omitempty"`
	UID         string `json:"uid,omitempty" yaml:"uid,omitempty"`
	UserFilter  string `json:"user_filter,omitempty" yaml:"user_filter,omitempty"`
}

type Auth struct {
	conf   *Config
	logger log.Logger
}

func New(conf *Config) auth.Auth {
	return &Auth{conf: conf, logger: log.Module("auth:ldap")}
}

func (provider *Auth) GetUser(username string) (*auth.AuthedUser, error) {
	return provider.getUser(username, nil)
}

func (provider *Auth) getUser(username string, cb func(l *lp.Conn, user *auth.AuthedUser) error) (*auth.AuthedUser, error) {
	log.WithFields(log.Fields{"username": username}).Debugf("ldap get user")

	res, err := provider.getConnection(func(l *lp.Conn) (interface{}, error) {
		searchReq := lp.NewSearchRequest(
			provider.conf.BaseDN,
			lp.ScopeWholeSubtree,
			lp.NeverDerefAliases,
			0,
			0,
			false,
			fmt.Sprintf("(&(objectClass=organizationalPerson)(%s=%s))", provider.conf.UID, lp.EscapeFilter(username)),
			[]string{"objectguid", provider.conf.UID, provider.conf.DisplayName, "userAccountControl"},
			nil,
		)

		sr, err := l.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP 用户查询失败: %w", err)
		}

		if len(sr.Entries) != 1 {
			return nil, fmt.Errorf("用户不存在")
		}

		// 514-禁用 512-启用
		if sr.Entries[0].GetAttributeValue("userAccountControl") == "514" {
			return nil, errors.New("LDAP 用户账户已禁用")
		}

		authedUser := buildAuthedUserFromLDAPEntry(provider.conf, sr.Entries[0])

		if cb != nil {
			if err := cb(l, &authedUser); err != nil {
				return nil, err
			}
		}

		return &authedUser, nil
	})
	if err != nil {
		return nil, err
	}

	return res.(*auth.AuthedUser), nil
}

func (provider *Auth) getConnection(cb func(l *lp.Conn) (interface{}, error)) (interface{}, error) {
	l, err := lp.DialURL(provider.conf.URL)
	if err != nil {
		return nil, fmt.Errorf("无法连接 LDAP 服务器: %w", err)
	}
	defer l.Close()

	l.SetTimeout(5 * time.Second)
	if err := l.Bind(provider.conf.Username, provider.conf.Password); err != nil {
		return nil, fmt.Errorf("LDAP 服务器鉴权失败: %w", err)
	}

	return cb(l)
}

func (provider *Auth) Login(username, password string) (*auth.AuthedUser, error) {
	return provider.getUser(username, func(l *lp.Conn, user *auth.AuthedUser) error {
		return l.Bind(username, password)
	})
}

func buildAuthedUserFromLDAPEntry(conf *Config, entry *lp.Entry) auth.AuthedUser {
	userStatus := 1
	if entry.GetAttributeValue("userAccountControl") == "514" {
		userStatus = 0
	}

	return auth.AuthedUser{
		UUID:    uuid.Must(uuid.FromBytes(entry.GetRawAttributeValue("objectGUID"))).String(),
		Name:    entry.GetAttributeValue(conf.DisplayName),
		Account: entry.GetAttributeValue(conf.UID),
		Status:  int8(userStatus),
	}
}

func (provider *Auth) Users() ([]auth.AuthedUser, error) {
	res, err := provider.getConnection(func(l *lp.Conn) (interface{}, error) {
		searchReq := lp.NewSearchRequest(
			provider.conf.BaseDN,
			lp.ScopeWholeSubtree,
			lp.NeverDerefAliases,
			0,
			0,
			false,
			fmt.Sprintf("(&(objectClass=organizationalPerson)(memberOf=%s))", lp.EscapeFilter(provider.conf.UserFilter)),
			[]string{"objectguid", provider.conf.UID, provider.conf.DisplayName, "userAccountControl"},
			nil,
		)

		sr, err := l.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP 用户查询失败: %w", err)
		}

		authedUsers := make([]auth.AuthedUser, 0)
		for _, ent := range sr.Entries {
			authedUsers = append(authedUsers, buildAuthedUserFromLDAPEntry(provider.conf, ent))
		}

		return authedUsers, nil
	})

	if err != nil {
		return nil, err
	}

	return res.([]auth.AuthedUser), nil
}
