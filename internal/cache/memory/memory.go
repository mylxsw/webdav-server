package memory

import (
	"time"

	"github.com/mylxsw/webdav-server/internal/cache"
	cacheLib "github.com/patrickmn/go-cache"
)

type memoryCache struct {
	cache *cacheLib.Cache
}

func NewMemoryCache() cache.Cache {
	return &memoryCache{cache: cacheLib.New(24*time.Hour, time.Minute)}
}

func (cac *memoryCache) Set(k string, x string, d time.Duration) error {
	cac.cache.Set(k, x, d)
	return nil
}

func (cac *memoryCache) Get(k string) (string, error) {
	val, ok := cac.cache.Get(k)
	if !ok {
		return "", cache.ErrCacheMissed
	}

	return val.(string), nil
}

func (cac *memoryCache) Delete(k string) error {
	cac.cache.Delete(k)
	return nil
}
