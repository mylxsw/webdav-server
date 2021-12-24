package misc

import (
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/webdav-server/internal/auth/ldap"
	"github.com/mylxsw/webdav-server/internal/auth/local"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(ldap.LDAPConfigBuilder())
	cc.MustSingletonOverride(local.LocalConfigBuilder())

	cc.MustSingletonOverride(New)
}

func (p Provider) Boot(cc infra.Resolver) {
}

func (p Provider) ShouldLoad(c infra.FlagContext) bool {
	return str.InIgnoreCase(c.String("auth"), []string{"misc"})
}
