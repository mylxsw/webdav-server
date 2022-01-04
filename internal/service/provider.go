package service

import (
	"github.com/mylxsw/glacier/infra"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(NewAuthService)
}
