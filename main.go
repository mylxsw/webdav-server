package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mylxsw/asteria/formatter"
	"github.com/mylxsw/asteria/level"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/asteria/writer"
	"github.com/mylxsw/container"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/starter/application"
	"github.com/mylxsw/webdav-server/internal/auth/ldap"
	"github.com/mylxsw/webdav-server/internal/server"
	"github.com/urfave/cli"
	"github.com/urfave/cli/altsrc"
	"golang.org/x/net/webdav"
	"gopkg.in/yaml.v2"
)

var Version = "1.0"
var GitCommit = "5dbef13fb456f51a5d29464d"

type Rules struct {
	Rules   []*server.Rule `json:"rules,omitempty" yaml:"rules,omitempty"`
	Prefix  string         `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	NoSniff bool           `json:"no_sniff,omitempty" yaml:"no_sniff,omitempty"`
	Scope   string         `json:"scope,omitempty" yaml:"scope,omitempty"`
	Modify  bool           `json:"modify,omitempty" yaml:"modify,omitempty"`
}

func (rules *Rules) Init() {
	for _, rule := range rules.Rules {
		rule.Init()
	}

	if rules.Prefix == "" {
		rules.Prefix = "/"
	}
	if rules.Scope == "" {
		rules.Scope = "."
	}
}

func main() {
	app := application.Create(fmt.Sprintf("%s %s", Version, GitCommit))
	app.AddFlags(altsrc.NewStringFlag(cli.StringFlag{
		Name:  "listen",
		Usage: "服务监听地址",
		Value: ":8080",
	}))
	app.AddFlags(altsrc.NewBoolFlag(cli.BoolFlag{
		Name:  "debug",
		Usage: "是否使用调试模式，调试模式下，静态资源使用本地文件",
	}))
	app.AddFlags(altsrc.NewStringFlag(cli.StringFlag{
		Name:  "log_path",
		Usage: "日志文件输出目录（非文件名），默认为空，输出到标准输出",
	}))

	app.AddFlags(altsrc.NewStringFlag(cli.StringFlag{
		Name:   "ldap_url",
		Usage:  "LDAP 服务器地址",
		Value:  "ldap://127.0.0.1:389",
		EnvVar: "LDAP_URL",
	}))
	app.AddFlags(altsrc.NewStringFlag(cli.StringFlag{
		Name:   "ldap_username",
		Usage:  "LDAP 账号",
		EnvVar: "LDAP_USER",
	}))
	app.AddFlags(altsrc.NewStringFlag(cli.StringFlag{
		Name:   "ldap_password",
		Usage:  "LDAP 密码",
		EnvVar: "LDAP_PASSWORD",
	}))
	app.AddFlags(altsrc.NewStringFlag(cli.StringFlag{
		Name:   "ldap_base_dn",
		Usage:  "LDAP base dn",
		Value:  "dc=example,dc=com",
		EnvVar: "LDAP_BASE_DN",
	}))
	app.AddFlags(altsrc.NewStringFlag(cli.StringFlag{
		Name:   "ldap_user_filter",
		Usage:  "LDAP user filter",
		Value:  "CN=all-staff,CN=Users,DC=example,DC=com",
		EnvVar: "LDAP_USER_FILTER",
	}))

	app.AddFlags(altsrc.NewBoolFlag(cli.BoolFlag{
		Name:  "auth",
		Usage: "enable auth",
	}))

	app.AddFlags(altsrc.NewBoolFlag(cli.BoolFlag{
		Name:  "cors",
		Usage: "enable cors",
	}))
	app.AddFlags(altsrc.NewBoolFlag(cli.BoolFlag{
		Name:  "cors-credentials",
		Usage: "enable cors credentials",
	}))
	app.AddFlags(altsrc.NewStringSliceFlag(cli.StringSliceFlag{
		Name:  "allowed-headers",
		Usage: "",
	}))
	app.AddFlags(altsrc.NewStringSliceFlag(cli.StringSliceFlag{
		Name:  "allowed-hosts",
		Usage: "",
	}))
	app.AddFlags(altsrc.NewStringSliceFlag(cli.StringSliceFlag{
		Name:  "allowed-methods",
		Usage: "",
	}))
	app.AddFlags(altsrc.NewStringSliceFlag(cli.StringSliceFlag{
		Name:  "exposed-headers",
		Usage: "",
	}))

	app.AddFlags(altsrc.NewStringFlag(cli.StringFlag{
		Name:  "rules",
		Usage: "Rules config file",
		Value: "rules.yaml",
	}))

	app.BeforeServerStart(func(cc container.Container) error {
		stackWriter := writer.NewStackWriter()
		cc.MustResolve(func(ctx context.Context, c infra.FlagContext) {
			if !c.Bool("debug") {
				log.All().LogLevel(level.Info)
			}

			logPath := c.String("log_path")
			if logPath == "" {
				stackWriter.PushWithLevels(writer.NewStdoutWriter())
				return
			}

			log.All().LogFormatter(formatter.NewJSONFormatter())
			stackWriter.PushWithLevels(writer.NewDefaultRotatingFileWriter(ctx, func(le level.Level, module string) string {
				return filepath.Join(logPath, fmt.Sprintf("%s-%s.log", time.Now().Format("20060102"), le.GetLevelName()))
			}))
		})

		stackWriter.PushWithLevels(
			NewErrorCollectorWriter(app.Container()),
			level.Error,
			level.Emergency,
			level.Critical,
		)
		log.All().LogWriter(stackWriter)

		return nil
	})

	app.Singleton(func(c infra.FlagContext) (net.Listener, error) {
		return net.Listen("tcp", c.String("listen"))
	})

	app.Singleton(func(c infra.FlagContext) *ldap.Config {
		return &ldap.Config{
			URL:         c.String("ldap_url"),
			BaseDN:      c.String("ldap_base_dn"),
			Username:    c.String("ldap_username"),
			Password:    c.String("ldap_password"),
			DisplayName: "displayName",
			UID:         "sAMAccountName",
			UserFilter:  c.String("ldap_user_filter"),
		}
	})
	app.Singleton(ldap.New)

	app.Singleton(func(c infra.FlagContext) *server.Config {
		data, err := ioutil.ReadFile(c.String("rules"))
		if err != nil {
			panic(fmt.Errorf("rules file %s does not exist: %v", c.String("rules"), err))
		}

		var rules Rules
		if err := yaml.Unmarshal(data, &rules); err != nil {
			panic(err)
		}

		rules.Init()

		log.WithFields(log.Fields{"rules": rules}).Debug("load rules")

		allowedHeaders := c.StringSlice("allowed-headers")
		allowedHosts := c.StringSlice("allowed-hosts")
		allowedMethods := c.StringSlice("allowed-methods")
		exposeHeaders := c.StringSlice("exposed-headers")

		return &server.Config{
			Prefix:      rules.Prefix,
			AuthEnabled: c.Bool("auth"),
			NoSniff:     rules.NoSniff,
			Cors: server.CorsConfig{
				Enabled:        c.Bool("cors"),
				Credentials:    c.Bool("cors-credentials"),
				AllowedHeaders: sliceOrAsterisk(allowedHeaders),
				AllowedHosts:   sliceOrAsterisk(allowedHosts),
				AllowedMethods: sliceOrAsterisk(allowedMethods),
				ExposedHeaders: exposeHeaders,
			},
			DefaultUser: server.User{
				Scope:  rules.Scope,
				Modify: rules.Modify,
				Rules:  rules.Rules,
				Handler: &webdav.Handler{
					Prefix: rules.Prefix,
					FileSystem: server.WebDavDir{
						Dir:     webdav.Dir(rules.Scope),
						NoSniff: rules.NoSniff,
					},
					LockSystem: webdav.NewMemLS(),
				},
			},
		}
	})

	app.Main(func(conf *server.Config) {
		log.With(conf).Debug("load config")
	})

	app.Provider(server.Provider{})

	if err := app.Run(os.Args); err != nil {
		log.Errorf("exit with error: %s", err)
	}
}

type ErrorCollectorWriter struct {
	cc container.Container
}

func NewErrorCollectorWriter(cc container.Container) *ErrorCollectorWriter {
	return &ErrorCollectorWriter{cc: cc}
}

func (e *ErrorCollectorWriter) Write(le level.Level, module string, message string) error {
	// TODO  Error collector implementation
	return nil
}

func (e *ErrorCollectorWriter) ReOpen() error {
	return nil
}

func (e *ErrorCollectorWriter) Close() error {
	return nil
}

func sliceOrAsterisk(src []string) []string {
	if len(src) == 0 {
		return []string{"*"}
	}
	return src
}
