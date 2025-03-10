package cache

import (
	"github.com/patrickmn/go-cache"
	"golang.org/x/net/dns/dnsmessage"
	"sync"
	"time"
)

type RecordsCache struct {
	records *cache.Cache
	mu      sync.Mutex
}

const (
	defaultExpiration = 1 * time.Hour
	purgeTime         = 1 * time.Hour
)

func NewRecordsCache() *RecordsCache {
	Cache := cache.New(defaultExpiration, purgeTime)
	return &RecordsCache{
		records: Cache,
	}
}

func (rc *RecordsCache) Get(name string) (dnsmessage.Resource, bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	record, ok := rc.records.Get(name)
	if ok {
		res := record.(dnsmessage.Resource)
		return res, ok
	}
	return dnsmessage.Resource{}, false
}

func (rc *RecordsCache) Set(resource dnsmessage.Resource) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.records.Set(resource.Header.Name.String(), resource, time.Duration(resource.Header.TTL)*time.Second)
}
