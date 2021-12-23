package server

import (
	"context"

	"github.com/mylxsw/glacier/infra"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(New)
}

func (p Provider) Boot(cc infra.Resolver) {
}

func (p Provider) Daemon(ctx context.Context, app infra.Resolver) {
	app.MustResolve(func(server *Server) {
		server.Start(ctx)
	})
}
