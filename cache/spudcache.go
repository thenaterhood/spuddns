package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

var activeSpudCache *spudcache

type spudcache struct {
	cache          map[string][]byte
	expireCallback ExpireCallbackFn
	config         CacheConfig
	cacheMutex     sync.RWMutex
}

var ErrEntryNotFound = errors.New("entry not found")

func getSpudcache(keep bool, config CacheConfig) (Cache, error) {

	if keep && activeSpudCache != nil {
		return activeSpudCache, nil
	}

	if activeSpudCache != nil {
		activeSpudCache = nil
	}

	cache := spudcache{
		cache:          map[string][]byte{},
		expireCallback: nil,
		config:         config,
		cacheMutex:     sync.RWMutex{},
	}

	activeSpudCache = &cache
	return activeSpudCache, nil
}

func (c *spudcache) set(key string, value []byte) error {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	c.cache[key] = value

	return nil
}

func (c *spudcache) get(key string) ([]byte, error) {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()

	val, ok := c.cache[key]
	if !ok {
		return nil, ErrEntryNotFound
	}

	return val, nil
}

func (c *spudcache) remove(key string) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	delete(c.cache, key)
}

func (c *spudcache) CacheDnsResponse(question dns.Question, response models.DnsResponse) error {
	key := getDnsQuestionCacheKey(question)

	if response.IsEmpty() {
		return nil
	}

	answers, err := response.Answers()
	if err != nil {
		return err
	}

	cache_entry := cacheEntry{
		Dns:      answers,
		Expires:  response.Expires,
		Resolver: response.Resolver,
	}

	value, err := json.Marshal(cache_entry)

	if err != nil {
		return err
	}

	ret := c.set(key, value)

	if c.expireCallback != nil {
		go func(question dns.Question, response models.DnsResponse) {
			time.Sleep(response.GetTtl() - 10*time.Second)

			retrieveCount := 0
			var cached cacheEntry
			key := getDnsQuestionCacheKey(question)

			raw_value, err := c.get(key)
			if err == nil {
				err = json.Unmarshal(raw_value, &cached)
				if err == nil {
					retrieveCount = cached.RequestCount
				}
			}

			keep := c.expireCallback(question, response, retrieveCount, c)
			if !keep {
				c.remove(key)
			}
		}(question, response)
	}

	return ret
}

func (c *spudcache) getDnsResponse(question dns.Question) (*models.DnsResponse, error) {
	timer := c.config.Metrics.GetCacheReadTimer()
	defer c.config.Metrics.ObserveTimer(timer)

	key := getDnsQuestionCacheKey(question)

	raw_value, err := c.get(key)

	if err == ErrEntryNotFound {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var value cacheEntry

	err = json.Unmarshal(raw_value, &value)
	if err != nil {
		return nil, err
	}

	if value.Expires.Before(time.Now()) {
		c.remove(key)
		return nil, nil
	}

	response, err := models.NewDnsResponseFromDnsAnswers(value.Dns)
	if err != nil {
		return nil, err
	}

	response.FromCache = true
	response.Expires = value.Expires
	response.Resolver = value.Resolver

	value.RequestCount += 1

	go func() {
		marshalled, err := json.Marshal(value)

		if err != nil {
			return
		}
		c.set(key, marshalled)
	}()

	return response, nil
}

func (c *spudcache) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	c.config.Logger.Debug("attempting to resolve from cache", "qname", q.FirstQuestion().Name)

	if q.FirstQuestion() == nil {
		return nil, fmt.Errorf("query question was nil")
	}
	return c.getDnsResponse(*q.FirstQuestion())
}

func (c *spudcache) SetExpireCallback(cb ExpireCallbackFn) {
	c.expireCallback = cb
}
