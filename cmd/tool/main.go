package main

import (
	"flag"
	"github.com/mylxsw/webdav-server/internal/auth/ldap"
	"github.com/mylxsw/webdav-server/internal/config"
	"io/ioutil"
	"os"

	"github.com/mylxsw/asteria/log"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
)

func main() {
	var action, configPath string

	flag.StringVar(&action, "action", "", "执行的动作，支持 encrypt|ldap-users")
	flag.StringVar(&configPath, "config", "./webdav-server.yaml", "要加密的配置文件路径")
	flag.Parse()

	switch action {
	case "encrypt":
		encryptConfigFile(configPath)
	case "ldap-users":
		listLDAPUsers(configPath)
	}
}

func listLDAPUsers(configPath string) {
	conf, err := config.LoadConfFromFile(configPath)
	if err != nil {
		panic(err)
	}

	ldapAuth := ldap.New(&conf.LDAP, &conf.Users)
	users, err := ldapAuth.Users()
	if err != nil {
		panic(err)
	}

	for _, user := range users {
		log.With(user).Infof("user found")
	}
}

func encryptConfigFile(configPath string) {
	conf, err := config.LoadConfFromFile(configPath)
	if err != nil {
		panic(err)
	}

	for i, user := range conf.Users.Local {
		if user.Algo == "" {
			encrypted, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			if err != nil {
				log.Errorf("encrypt password for %s failed: %v", user.Account, err)
				continue
			}

			log.With(user).Debugf("password encrypted for %s", user.Account)

			conf.Users.Local[i].Algo = "bcrypt"
			conf.Users.Local[i].Password = string(encrypted)
		}
	}

	generated, err := yaml.Marshal(conf)
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(configPath, generated, os.ModePerm); err != nil {
		panic(err)
	}
}
