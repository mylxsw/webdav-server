package server

import (
	"regexp"
	"strings"

	"github.com/mylxsw/webdav-server/internal/auth"
	"golang.org/x/net/webdav"
)

type Config struct {
	Prefix      string     `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	AuthEnabled bool       `json:"auth_enabled,omitempty" yaml:"auth_enabled,omitempty"`
	NoSniff     bool       `json:"no_sniff,omitempty" yaml:"no_sniff,omitempty"`
	Cors        CorsConfig `json:"cors,omitempty" yaml:"cors,omitempty"`
	DefaultUser User       `json:"default_user,omitempty" yaml:"default_user,omitempty"`
}

type CorsConfig struct {
	Enabled        bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Credentials    bool     `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	AllowedHeaders []string `json:"allowed_headers,omitempty" yaml:"allowed_headers,omitempty"`
	AllowedHosts   []string `json:"allowed_hosts,omitempty" yaml:"allowed_hosts,omitempty"`
	AllowedMethods []string `json:"allowed_methods,omitempty" yaml:"allowed_methods,omitempty"`
	ExposedHeaders []string `json:"exposed_headers,omitempty" yaml:"exposed_headers,omitempty"`
}

type User struct {
	Username string          `json:"username,omitempty" yaml:"username,omitempty"`
	Password string          `json:"password,omitempty" yaml:"password,omitempty"`
	Scope    string          `json:"scope,omitempty" yaml:"scope,omitempty"`
	Modify   bool            `json:"modify,omitempty" yaml:"modify,omitempty"`
	Rules    []*Rule         `json:"rules,omitempty" yaml:"rules,omitempty"`
	Handler  *webdav.Handler `json:"-" yaml:"-"`
}

// Allowed checks if the user has permission to access a directory/file
func (u User) Allowed(url string, noModification bool) bool {
	var rule *Rule
	i := len(u.Rules) - 1

	for i >= 0 {
		rule = u.Rules[i]

		isAllowed := rule.Allow && (noModification || rule.Modify)
		if rule.Regex {
			if rule.Regexp.MatchString(url) {
				return isAllowed
			}
		} else if strings.HasPrefix(url, rule.Path) {
			return isAllowed
		}

		i--
	}

	return noModification || u.Modify
}

type Rule struct {
	Regex  bool           `json:"regex,omitempty" yaml:"regex,omitempty"`
	Allow  bool           `json:"allow,omitempty" yaml:"allow,omitempty"`
	Modify bool           `json:"modify,omitempty" yaml:"modify,omitempty"`
	Path   string         `json:"path,omitempty" yaml:"path,omitempty"`
	Regexp *regexp.Regexp `json:"-" yaml:"-"`
}

func (rule *Rule) Init() {
	if rule.Regex {
		rule.Regexp = regexp.MustCompile(rule.Path)
	}
}

func authUserToWebdavUser(authed auth.AuthedUser, conf *Config) User {
	user := User{
		Username: authed.Account,
		Scope:    conf.DefaultUser.Scope,
		Modify:   conf.DefaultUser.Modify,
		Rules:    conf.DefaultUser.Rules,
	}

	user.Handler = &webdav.Handler{
		Prefix: conf.DefaultUser.Handler.Prefix,
		FileSystem: WebDavDir{
			Dir:     webdav.Dir(user.Scope),
			NoSniff: conf.NoSniff,
		},
		LockSystem: webdav.NewMemLS(),
	}

	return user
}
