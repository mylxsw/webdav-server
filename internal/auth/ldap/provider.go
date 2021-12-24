package ldap

import (
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(New)
	cc.MustSingletonOverride(LDAPConfigBuilder())
}

func (p Provider) Boot(cc infra.Resolver) {
}

func (p Provider) ShouldLoad(c infra.FlagContext) bool {
	return str.InIgnoreCase(c.String("auth"), []string{"ldap"})
}

func LDAPConfigBuilder() func(c infra.FlagContext) *Config {
	return func(c infra.FlagContext) *Config {
		return &Config{
			URL:         c.String("ldap-url"),
			BaseDN:      c.String("ldap-basedn"),
			Username:    c.String("ldap-username"),
			Password:    c.String("ldap-password"),
			DisplayName: "displayName",
			UID:         "sAMAccountName",
			UserFilter:  c.String("ldap-filter"),
		}
	}
}
