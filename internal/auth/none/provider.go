package none

import (
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(New)
}

func (p Provider) Boot(cc infra.Resolver) {
}

func (p Provider) ShouldLoad(c infra.FlagContext) bool {
	return str.InIgnoreCase(c.String("auth"), []string{"none"})
}
