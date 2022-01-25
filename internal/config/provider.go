package config

import (
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/glacier/infra"
)

type Provider struct{}

func (pro Provider) Register(binder infra.Binder) {
	binder.MustSingletonOverride(func(conf *Config) *LDAP { return &conf.LDAP })
	binder.MustSingletonOverride(func(conf *Config) *Users { return &conf.Users })
	binder.MustSingletonOverride(func(conf *Config) *Server { return &conf.Server })
	binder.MustSingletonOverride(func(conf *Config) *UserGroupRules {
		userGroupRules := UserGroupRules{
			Users:  map[string][]Rule{},
			Groups: map[string][]Rule{},
		}

		for _, rule := range conf.Rules {
			for _, user := range rule.Users {
				if _, ok := userGroupRules.Users[user]; !ok {
					userGroupRules.Users[user] = make([]Rule, 0)
				}

				userGroupRules.Users[user] = append(userGroupRules.Users[user], rule)
			}
			for _, group := range rule.Groups {
				if _, ok := userGroupRules.Groups[group]; !ok {
					userGroupRules.Groups[group] = make([]Rule, 0)
				}

				userGroupRules.Groups[group] = append(userGroupRules.Groups[group], rule)
			}
		}

		return &userGroupRules
	})
}

func (pro Provider) Boot(resolver infra.Resolver) {
	resolver.MustResolve(func(conf *Config) {
		log.With(conf).Debugf("boot configuration")
	})
}
