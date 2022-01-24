package server

import (
	"context"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/webdav-server/internal/config"
	"github.com/mylxsw/webdav-server/internal/service"
	"golang.org/x/net/webdav"
	"net"

	"github.com/mylxsw/glacier/infra"
)

type Provider struct{}

func (p Provider) Register(binder infra.Binder) {
	binder.MustSingletonOverride(func(conf *config.Config) (net.Listener, error) {
		return net.Listen("tcp", conf.Listen)
	})
	binder.MustSingletonOverride(func(resolver infra.Resolver, handler *webdav.Handler, authSrv service.AuthService) Server {
		return New(resolver, log.Module("audit"), handler, authSrv)
	})
	binder.MustSingletonOverride(func(conf *config.Server) *webdav.Handler {
		return &webdav.Handler{
			Prefix: conf.Prefix,
			FileSystem: WebDavDir{
				Dir:     webdav.Dir(conf.Scope),
				NoSniff: conf.NoSniff,
			},
			LockSystem: webdav.NewMemLS(),
		}
	})
}

func (p Provider) Daemon(ctx context.Context, app infra.Resolver) {
	app.MustResolve(func(server Server, listener net.Listener) {
		server.Start(ctx, listener)
	})
}
