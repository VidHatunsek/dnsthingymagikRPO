package recordcache

import (
	"dnsthingymagik/resolver/entities"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"sync"
	"time"
)

type Cache struct {
	mu      sync.RWMutex
	records map[string][]entities.Record
}

func NewCache() *Cache {
	c := &Cache{
		records: make(map[string][]entities.Record),
	}
	go c.cleanupExpiredRecords()
	return c
}

func generateKey(name dnsmessage.Name, rtype dnsmessage.Type) string {
	return fmt.Sprintf("%s:%d", name.String(), rtype)
}

func (c *Cache) Set(record entities.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := generateKey(record.Name, record.RType)
	record.ExpireAt = time.Now().Add(time.Duration(record.TTL) * time.Second)

	existingRecords, exists := c.records[key]
	if exists {
		for _, existingRecord := range existingRecords {
			if existingRecord.IP.Equal(record.IP) {
				return
			}
		}
	}

	c.records[key] = append(c.records[key], record)
}

func (c *Cache) Get(name dnsmessage.Name, rtype dnsmessage.Type) ([]entities.Record, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := generateKey(name, rtype)
	records, exists := c.records[key]
	if !exists {
		return nil, false
	}

	validRecords := []entities.Record{}
	now := time.Now()
	for _, record := range records {
		remainingTTL := uint32(record.ExpireAt.Sub(now).Seconds())
		if remainingTTL > 0 {
			record.TTL = remainingTTL
			validRecords = append(validRecords, record)
		}
	}

	if len(validRecords) == 0 {
		delete(c.records, key)
		return nil, false
	}

	c.records[key] = validRecords
	return validRecords, true
}

func (c *Cache) cleanupExpiredRecords() {
	ticker := time.NewTicker(time.Hour) // Run every hour
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, records := range c.records {
			validRecords := []entities.Record{}
			for _, record := range records {
				if now.Before(record.ExpireAt) {
					validRecords = append(validRecords, record)
				}
			}
			if len(validRecords) == 0 {
				delete(c.records, key)
			} else {
				c.records[key] = validRecords
			}
		}
		c.mu.Unlock()
	}
}
