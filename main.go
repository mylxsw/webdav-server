package main

import (
	"context"
	"fmt"
	"github.com/mylxsw/glacier"
	"io/ioutil"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/mylxsw/asteria/formatter"
	"github.com/mylxsw/asteria/level"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/asteria/writer"
	"github.com/mylxsw/container"
	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/glacier/starter/application"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/webdav-server/internal/auth/ldap"
	"github.com/mylxsw/webdav-server/internal/auth/local"
	"github.com/mylxsw/webdav-server/internal/auth/misc"
	"github.com/mylxsw/webdav-server/internal/auth/none"
	"github.com/mylxsw/webdav-server/internal/cache/memory"
	"github.com/mylxsw/webdav-server/internal/server"
	"github.com/mylxsw/webdav-server/internal/service"
	"golang.org/x/net/webdav"
	"gopkg.in/yaml.v2"
)

var Version = "1.0"
var GitCommit = "5dbef13fb456f51a5d29464d"

type Rules struct {
	Rules      []server.Rule `json:"rules,omitempty" yaml:"rules,omitempty"`
	UserRules  []UserRule    `json:"userRules,omitempty" yaml:"userRules,omitempty"`
	Prefix     string        `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	NoSniff    bool          `json:"noSniff,omitempty" yaml:"noSniff,omitempty"`
	Scope      string        `json:"scope,omitempty" yaml:"scope,omitempty"`
	Access     string        `json:"access,omitempty" yaml:"access,omitempty"`
	UserAccess string        `json:"userAccess,omitempty" yaml:"userAccess,omitempty"`
}

type UserRule struct {
	Regex  bool     `json:"regex,omitempty" yaml:"regex,omitempty"`
	Access string   `json:"access,omitempty" yaml:"access,omitempty"`
	Path   string   `json:"path,omitempty" yaml:"path,omitempty"`
	Users  []string `json:"users,omitempty" yaml:"users,omitempty"`
}

func (rules Rules) Init() Rules {
	rules.Access = strings.ToUpper(rules.Access)
	rules.UserAccess = strings.ToUpper(rules.UserAccess)

	if rules.Scope == "" {
		rules.Scope = "."
	}

	for i, rule := range rules.Rules {
		rules.Rules[i] = rule.Init()
	}

	return rules
}

func main() {
	app := application.Create(fmt.Sprintf("%s %s", Version, GitCommit))

	app.AddStringFlag("listen", ":8080", "服务监听地址")
	app.AddBoolFlag("debug", "是否使用调试模式")
	app.AddBoolFlag("log-json", "日志以 json 格式输出")
	app.AddStringFlag("log-path", "", "日志文件输出目录（非文件名），默认为空，输出到标准输出")
	app.AddStringFlag("cache-driver", "memory", "缓存驱动，当前仅支持 memory")

	app.AddStringFlag("auth", "none", "auth type: none|ldap|local|misc")
	app.AddStringFlag("rules", "rules.yaml", "Rules config file")

	app.AddFlags(glacier.StringEnvFlag("ldap-url", "ldap://127.0.0.1:389", "LDAP 服务器地址", "LDAP_URL"))
	app.AddFlags(glacier.StringEnvFlag("ldap-username", "", "LDAP 账号", "LDAP_USER"))
	app.AddFlags(glacier.StringEnvFlag("ldap-password", "", "LDAP 密码", "LDAP_PASSWORD"))
	app.AddFlags(glacier.StringEnvFlag("ldap-basedn", "dc=example,dc=com", "LDAP base dn", "LDAP_BASE_DN"))
	app.AddFlags(glacier.StringEnvFlag("ldap-filter", "CN=all-staff,CN=Users,DC=example,DC=com", "LDAP user filter", "LDAP_USER_FILTER"))

	app.AddStringFlag("local-users", "local-users.yaml", "本地用户来源配置文件")

	app.AddBoolFlag("cors", "enable cors")
	app.AddBoolFlag("cors-credentials", "enable cors credentials")
	app.AddStringSliceFlag("allowed-headers", []string{}, "")
	app.AddStringSliceFlag("allowed-hosts", []string{}, "")
	app.AddStringSliceFlag("allowed-methods", []string{}, "")
	app.AddStringSliceFlag("exposed-headers", []string{}, "")

	app.Singleton(configBuilder)
	app.BeforeServerStart(beforeServerStart)

	app.Singleton(func(c infra.FlagContext) (net.Listener, error) {
		return net.Listen("tcp", c.String("listen"))
	})

	app.Main(func(conf *server.Config) {
		log.With(conf).Debug("load config")
	})

	app.Provider(server.Provider{}, service.Provider{})
	app.Provider(ldap.Provider{}, none.Provider{}, local.Provider{}, misc.Provider{})
	app.Provider(memory.Provider{})

	application.MustRun(app)
}

func configBuilder(c infra.FlagContext) *server.Config {
	authType := strings.ToLower(c.String("auth"))
	if !str.InIgnoreCase(authType, []string{"none", "ldap", "local", "misc"}) {
		panic("invalid argument auth")
	}

	data, err := ioutil.ReadFile(c.String("rules"))
	if err != nil {
		panic(fmt.Errorf("rules file %s does not exist: %v", c.String("rules"), err))
	}

	var rules Rules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		panic(err)
	}

	rules = rules.Init()

	log.WithFields(log.Fields{"rules": rules}).Debug("load rules")

	allowedHeaders := c.StringSlice("allowed-headers")
	allowedHosts := c.StringSlice("allowed-hosts")
	allowedMethods := c.StringSlice("allowed-methods")
	exposeHeaders := c.StringSlice("exposed-headers")

	userRules := make(map[string][]server.Rule)
	for _, rule := range rules.UserRules {
		for _, u := range rule.Users {
			if _, ok := userRules[u]; !ok {
				userRules[u] = make([]server.Rule, 0)
			}

			userRules[u] = append(userRules[u], server.Rule{
				Access: rule.Access,
				Path:   rule.Path,
				Regex:  rule.Regex,
			}.Init())
		}
	}

	return &server.Config{
		Prefix:      rules.Prefix,
		AuthEnabled: authType != "none",
		NoSniff:     rules.NoSniff,
		Rules:       rules.Rules,
		UserRules:   userRules,
		Access:      rules.Access,
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
			Access: rules.UserAccess,
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
}

func beforeServerStart(cc container.Container) error {
	stackWriter := writer.NewStackWriter()
	cc.MustResolve(func(ctx context.Context, c infra.FlagContext) {
		if !c.Bool("debug") {
			log.All().LogLevel(level.Info)
		}

		if c.Bool("log-json") {
			log.All().LogFormatter(formatter.NewJSONFormatter())
		}

		logPath := c.String("log-path")
		if logPath == "" {
			stackWriter.PushWithLevels(writer.NewStdoutWriter())
			return
		}

		stackWriter.PushWithLevels(writer.NewDefaultRotatingFileWriter(ctx, func(le level.Level, module string) string {
			return filepath.Join(logPath, fmt.Sprintf("%s-%s.log", time.Now().Format("20060102"), le.GetLevelName()))
		}))
	})

	log.All().LogWriter(stackWriter)

	return nil
}

func sliceOrAsterisk(src []string) []string {
	if len(src) == 0 {
		return []string{"*"}
	}
	return src
}
