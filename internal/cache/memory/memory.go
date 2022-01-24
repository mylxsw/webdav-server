package memory

import (
	"time"

	"github.com/mylxsw/webdav-server/internal/cache"
	cacheLib "github.com/patrickmn/go-cache"
)

type memoryDriver struct {
	cache *cacheLib.Cache
}

func New() cache.Driver {
	return &memoryDriver{cache: cacheLib.New(24*time.Hour, time.Minute)}
}

func (cac *memoryDriver) Set(k string, x string, d time.Duration) error {
	cac.cache.Set(k, x, d)
	return nil
}

func (cac *memoryDriver) Get(k string) (string, error) {
	val, ok := cac.cache.Get(k)
	if !ok {
		return "", cache.ErrCacheMissed
	}

	return val.(string), nil
}

func (cac *memoryDriver) Delete(k string) error {
	cac.cache.Delete(k)
	return nil
}
