package ldap

import (
	"errors"
	"fmt"

	lp "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
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
	conf *Config
}

func (provider *Auth) CanRegister() bool {
	return false
}

func (provider *Auth) Register(username, password string) (*auth.AuthedUser, error) {
	return nil, fmt.Errorf("user register is not supported in ldap mode")
}

func New(conf *Config) auth.Auth {
	return &Auth{conf: conf}
}

func (provider *Auth) GetUser(username string) (*auth.AuthedUser, error) {
	conf := provider.conf

	l, err := lp.DialURL(conf.URL)
	if err != nil {
		return nil, fmt.Errorf("无法连接 LDAP 服务器: %w", err)
	}

	defer l.Close()

	if err := l.Bind(conf.Username, conf.Password); err != nil {
		return nil, fmt.Errorf("LDAP 服务器鉴权失败: %w", err)
	}

	searchReq := lp.NewSearchRequest(
		conf.BaseDN,
		lp.ScopeWholeSubtree,
		lp.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(%s=%s))", conf.UID, lp.EscapeFilter(username)),
		[]string{"objectguid", conf.UID, conf.DisplayName, "userAccountControl"},
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

	authedUser := buildAuthedUserFromLDAPEntry(conf, sr.Entries[0])
	return &authedUser, nil
}

func (provider *Auth) Login(username, password string) (*auth.AuthedUser, error) {
	conf := provider.conf

	l, err := lp.DialURL(conf.URL)
	if err != nil {
		return nil, fmt.Errorf("无法连接 LDAP 服务器: %w", err)
	}

	defer l.Close()

	if err := l.Bind(conf.Username, conf.Password); err != nil {
		return nil, fmt.Errorf("LDAP 服务器鉴权失败: %w", err)
	}

	searchReq := lp.NewSearchRequest(
		conf.BaseDN,
		lp.ScopeWholeSubtree,
		lp.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(%s=%s))", conf.UID, lp.EscapeFilter(username)),
		[]string{"objectguid", conf.UID, conf.DisplayName, "userAccountControl"},
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

	if err := l.Bind(sr.Entries[0].DN, password); err != nil {
		return nil, fmt.Errorf("用户密码错误: %w", err)
	}

	authedUser := buildAuthedUserFromLDAPEntry(conf, sr.Entries[0])
	return &authedUser, nil
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
	l, err := lp.DialURL(provider.conf.URL)
	if err != nil {
		return nil, fmt.Errorf("无法连接 LDAP 服务器: %w", err)
	}

	defer l.Close()

	if err := l.Bind(provider.conf.Username, provider.conf.Password); err != nil {
		return nil, fmt.Errorf("LDAP 服务器鉴权失败: %w", err)
	}

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
}
