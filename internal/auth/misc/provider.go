package misc

import (
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/webdav-server/internal/auth/ldap"
	"github.com/mylxsw/webdav-server/internal/auth/local"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(ldap.ConfigBuilder())
	cc.MustSingletonOverride(local.ConfigBuilder())

	cc.MustSingletonOverride(New)
}

func (p Provider) ShouldLoad(c infra.FlagContext) bool {
	return str.InIgnoreCase(c.String("auth"), []string{"misc"})
}
