package auth

import (
	"errors"
	"github.com/mylxsw/asteria/log"
	"github.com/mylxsw/go-utils/str"
	"github.com/mylxsw/webdav-server/internal/config"
)

type Author interface {
	Login(username, password string) (*AuthedUser, error)
	GetUser(username string) (*AuthedUser, error)
	Users() ([]AuthedUser, error)
}

type AuthedUser struct {
	Type    string   `json:"type" yaml:"type"`
	UUID    string   `json:"uuid" yaml:"uuid"`
	Name    string   `json:"name" yaml:"name"`
	Account string   `json:"account" yaml:"account"`
	Groups  []string `json:"groups" yaml:"groups"`
	Status  int8     `json:"status" yaml:"status"`
}

func (user AuthedUser) HasPrivilege(conf *config.Config, userGroupRules *config.UserGroupRules, method string, requestPath string) bool {
	log.F(log.M{"method": method, "path": requestPath, "user": user.Account, "groups": user.Groups}).Debugf("check privileges")

	// server=write
	if conf.Server.AccessMode == config.AccessModeWrite {
		return true
	}

	// server=read, read request
	readonlyRequest := str.InIgnoreCase(method, []string{"GET", "HEAD", "OPTIONS", "PROPFIND"})
	if conf.Server.AccessMode == config.AccessModeRead && readonlyRequest {
		return true
	}

	// 用户规则优先，寻找user/group最大权限
	if rules, ok := userGroupRules.Users[user.Account]; ok {
		for _, rule := range rules {
			if !rule.Matched(requestPath) {
				continue
			}

			if rule.AccessMode == config.AccessModeWrite {
				return true
			}

			if rule.AccessMode == config.AccessModeRead && readonlyRequest {
				return true
			}
		}
	}

	for _, userGroup := range user.Groups {
		if rules, ok := userGroupRules.Groups[userGroup]; ok {
			for _, rule := range rules {
				if !rule.Matched(requestPath) {
					continue
				}

				if rule.AccessMode == config.AccessModeWrite {
					return true
				}

				if rule.AccessMode == config.AccessModeRead && readonlyRequest {
					return true
				}
			}
		}
	}

	// server=read, write request
	// server=none, read|write request
	return false
}

var ErrNoSuchUser = errors.New("user not found")
var ErrInvalidPassword = errors.New("invalid password")
