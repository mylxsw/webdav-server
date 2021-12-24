package server

import (
	"regexp"
	"strings"

	"github.com/mylxsw/webdav-server/internal/auth"
	"golang.org/x/net/webdav"
)

type Config struct {
	Prefix      string            `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	AuthEnabled bool              `json:"authEnabled,omitempty" yaml:"authEnabled,omitempty"`
	NoSniff     bool              `json:"noSniff,omitempty" yaml:"noSniff,omitempty"`
	Cors        CorsConfig        `json:"cors,omitempty" yaml:"cors,omitempty"`
	DefaultUser User              `json:"defaultUser,omitempty" yaml:"defaultUser,omitempty"`
	Rules       []Rule            `json:"rules,omitempty" yaml:"rules,omitempty"`
	UserRules   map[string][]Rule `json:"userRules,omitempty" yaml:"userRules,omitempty"`
	Access      string            `json:"access,omitempty" yaml:"access,omitempty"`
}

// AccessMode 返回路径的访问权限模式
func (conf *Config) AccessMode(url string) string {
	for _, rule := range conf.Rules {
		if rule.Matched(url) {
			return rule.Access
		}
	}

	return conf.Access
}

type CorsConfig struct {
	Enabled        bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Credentials    bool     `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	AllowedHeaders []string `json:"allowedHeaders,omitempty" yaml:"allowedHeaders,omitempty"`
	AllowedHosts   []string `json:"allowedHosts,omitempty" yaml:"allowedHosts,omitempty"`
	AllowedMethods []string `json:"allowedMethods,omitempty" yaml:"allowedMethods,omitempty"`
	ExposedHeaders []string `json:"exposedHeaders,omitempty" yaml:"exposedHeaders,omitempty"`
}

type User struct {
	Username string          `json:"username,omitempty" yaml:"username,omitempty"`
	Password string          `json:"password,omitempty" yaml:"password,omitempty"`
	Scope    string          `json:"scope,omitempty" yaml:"scope,omitempty"`
	Access   string          `json:"access,omitempty" yaml:"access,omitempty"`
	Rules    []Rule          `json:"rules,omitempty" yaml:"rules,omitempty"`
	Handler  *webdav.Handler `json:"-" yaml:"-"`
}

// Allowed checks if the user has permission to access a directory/file
func (u User) Allowed(pathAccessMode, url string, readonlyRequest bool) bool {
	userAccess := u.buildUserAccessMode(url)
	if userAccess == "" {
		return false
	}

	if pathAccessMode == "RW" && userAccess == "RW" {
		return true
	}

	return readonlyRequest
}

func (u User) buildUserAccessMode(url string) string {
	for _, rule := range u.Rules {
		if !rule.Matched(url) {
			continue
		}

		return rule.Access
	}

	return u.Access
}

type Rule struct {
	Regex  bool           `json:"regex,omitempty" yaml:"regex,omitempty"`
	Access string         `json:"access,omitempty" yaml:"access,omitempty"`
	Path   string         `json:"path,omitempty" yaml:"path,omitempty"`
	Regexp *regexp.Regexp `json:"-" yaml:"-"`
}

func (rule Rule) Matched(url string) bool {
	if rule.Regex {
		if rule.Regexp.MatchString(url) {
			return true
		}
	} else if strings.HasPrefix(url, rule.Path) {
		return true
	}

	return false
}

func (rule Rule) Init() Rule {
	rule.Access = strings.ToUpper(rule.Access)
	if rule.Regex {
		rule.Regexp = regexp.MustCompile(rule.Path)
	}

	return rule
}

func authUserToWebdavUser(authed auth.AuthedUser, conf *Config) User {
	user := User{
		Username: authed.Account,
		Scope:    conf.DefaultUser.Scope,
		Access:   conf.DefaultUser.Access,
		Rules:    conf.DefaultUser.Rules,
	}

	if rules, ok := conf.UserRules[authed.Account]; ok {
		user.Rules = rules
	}

	user.Handler = conf.DefaultUser.Handler

	return user
}
