package local

import (
	"io/ioutil"

	"github.com/mylxsw/glacier/infra"
	"github.com/mylxsw/go-utils/str"
	"gopkg.in/yaml.v2"
)

type Provider struct{}

func (p Provider) Register(cc infra.Binder) {
	cc.MustSingletonOverride(New)
	cc.MustSingletonOverride(ConfigBuilder())
}

func (p Provider) ShouldLoad(c infra.FlagContext) bool {
	return str.InIgnoreCase(c.String("auth"), []string{"local"})
}

func ConfigBuilder() func(c infra.FlagContext) (*Config, error) {
	return func(c infra.FlagContext) (*Config, error) {
		confFile := c.String("local-users")
		if confFile == "" {
			return &Config{Users: make([]User, 0)}, nil
		}

		data, err := ioutil.ReadFile(confFile)
		if err != nil {
			return nil, err
		}

		var conf Config
		if err := yaml.Unmarshal(data, &conf); err != nil {
			return nil, err
		}

		return &conf, nil
	}
}
