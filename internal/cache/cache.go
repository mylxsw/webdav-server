package cache

import (
	"errors"
	"time"
)

type Cache interface {
	Set(k string, x string, d time.Duration) error
	Get(k string) (string, error)
	Delete(k string) error
}

var ErrCacheMissed = errors.New("not found")
