package config

import (
	"errors"
	"fmt"
	"github.com/mylxsw/go-utils/file"
	"github.com/mylxsw/go-utils/str"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"regexp"
	"strings"
)

const (
	AccessModeNone  = "none"
	AccessModeRead  = "read"
	AccessModeWrite = "write"
)

type Config struct {
	Verbose bool `json:"verbose" yaml:"verbose,omitempty"`

	Listen   string `json:"listen" yaml:"listen,omitempty"`
	HTTPS    bool   `json:"https" yaml:"https,omitempty"`
	CertFile string `json:"cert_file" yaml:"cert_file"`
	KeyFile  string `json:"key_file" yaml:"key_file"`

	LogPath     string `json:"log_path" yaml:"log_path,omitempty"`
	CacheDriver string `json:"cache_driver" yaml:"cache_driver"`
	AuthType    string `json:"auth_type" yaml:"auth_type"`

	Server Server `json:"server" yaml:"server"`
	Rules  []Rule `json:"rules" yaml:"rules"`

	LDAP  LDAP  `json:"ldap" yaml:"ldap,omitempty"`
	Users Users `json:"users,omitempty" yaml:"users,omitempty"`
}

type UserGroupRules struct {
	Users  map[string][]Rule
	Groups map[string][]Rule
}

type Rule struct {
	pattern *regexp.Regexp

	Path       string   `json:"path" yaml:"path"`
	AccessMode string   `json:"access_mode" yaml:"access_mode"`
	Users      []string `json:"users,omitempty" yaml:"users,omitempty"`
	Groups     []string `json:"groups,omitempty" yaml:"groups,omitempty"`
}

func (rule Rule) Matched(path string) bool {
	return rule.pattern.MatchString(path)
}

type Server struct {
	Scope      string `json:"scope" yaml:"scope"`
	Prefix     string `json:"prefix" yaml:"prefix"`
	NoSniff    bool   `json:"no_sniff" yaml:"no_sniff"`
	AccessMode string `json:"access_mode" yaml:"access_mode,omitempty"`
}

// populateDefault 填充默认值
func (conf Config) populateDefault() Config {
	if conf.AuthType == "" {
		conf.AuthType = "misc"
	}

	if conf.Listen == "" {
		conf.Listen = ":8080"
	}

	if conf.LDAP.DisplayName == "" {
		conf.LDAP.DisplayName = "displayName"
	}

	if conf.LDAP.UID == "" {
		conf.LDAP.UID = "sAMAccountName"
	}

	if conf.LDAP.UserFilter == "" {
		conf.LDAP.UserFilter = "CN=all-staff,CN=Users,DC=example,DC=com"
	}

	if conf.Server.AccessMode == "" {
		conf.Server.AccessMode = AccessModeRead
	}
	conf.Server.AccessMode = strings.ToLower(conf.Server.AccessMode)

	for i, rule := range conf.Rules {
		conf.Rules[i].pattern = regexp.MustCompilePOSIX(rule.Path)
		if rule.AccessMode == "" {
			conf.Rules[i].AccessMode = AccessModeRead
		}
	}

	return conf
}

// validate 配置合法性检查
func (conf Config) validate() error {
	if !str.In(conf.AuthType, []string{"misc", "ldap", "local"}) {
		return fmt.Errorf("invalid auth_type: must be one of misc|local|ldap")
	}

	if conf.HTTPS {
		if conf.CertFile == "" {
			return fmt.Errorf("invalid cert_file: cert_file is required when https=true")
		}

		if conf.KeyFile == "" {
			return fmt.Errorf("invalid key_file: key_file is required when https=true")
		}
	}

	if !str.In(conf.Server.AccessMode, []string{AccessModeNone, AccessModeRead, AccessModeWrite}) {
		return fmt.Errorf("invalid server.access_mode: must be one of none|read|write")
	}

	for i, rule := range conf.Rules {
		if _, err := regexp.CompilePOSIX(rule.Path); err != nil {
			return fmt.Errorf("invalid rules[%d].path: %v", i, err)
		}
	}

	return nil
}

// LDAP 域账号登录配置
type LDAP struct {
	URL         string `json:"url" yaml:"url,omitempty"`
	BaseDN      string `json:"base_dn" yaml:"base_dn,omitempty"`
	Username    string `json:"username" yaml:"username,omitempty"`
	Password    string `json:"-" yaml:"password,omitempty"`
	DisplayName string `json:"display_name" yaml:"display_name,omitempty"`
	UID         string `json:"uid" yaml:"uid,omitempty"`
	UserFilter  string `json:"user_filter" yaml:"user_filter,omitempty"`
}

// Users 用户配置
type Users struct {
	IgnoreAccountSuffix string      `json:"ignore_account_suffix" yaml:"ignore_account_suffix,omitempty"`
	Local               []LocalUser `json:"local,omitempty" yaml:"local,omitempty"`
	LDAP                []LDAPUser  `json:"ldap,omitempty" yaml:"ldap,omitempty"`
}

// LDAPUser ldap 用户配置
type LDAPUser struct {
	Account string   `json:"account" yaml:"account"`
	Group   string   `json:"group,omitempty" yaml:"group,omitempty"`
	Groups  []string `json:"groups,omitempty" yaml:"groups,omitempty"`
}

// GetUserGroups 获取用户所属 groups
func (user LDAPUser) GetUserGroups() []string {
	if user.Groups == nil {
		user.Groups = make([]string, 0)
	}
	if user.Group != "" {
		user.Groups = append(user.Groups, user.Group)
	}

	return str.Distinct(user.Groups)
}

// LocalUser 本地用户配置
type LocalUser struct {
	Name     string   `json:"name" yaml:"name"`
	Account  string   `json:"account" yaml:"account"`
	Password string   `json:"-" yaml:"password"`
	Group    string   `json:"group,omitempty" yaml:"group,omitempty"`
	Groups   []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	Algo     string   `json:"algo" yaml:"algo"`
}

// GetUserGroups 获取用户所属的 groups
func (user LocalUser) GetUserGroups() []string {
	if user.Groups == nil {
		user.Groups = make([]string, 0)
	}
	if user.Group != "" {
		user.Groups = append(user.Groups, user.Group)
	}

	return str.Distinct(user.Groups)
}

// LoadConfFromFile 从配置文件加载配置
func LoadConfFromFile(configPath string) (*Config, error) {
	if configPath == "" {
		return nil, errors.New("config file path is required")
	}

	if !file.Exist(configPath) {
		return nil, fmt.Errorf("config file %s not exist", configPath)
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}

	conf = conf.populateDefault()
	if err := conf.validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}
