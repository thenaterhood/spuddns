package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

var activeCache *inMemoryCache

type inMemoryCache struct {
	cache          *bigcache.BigCache
	expireCallback ExpireCallbackFn
	config         CacheConfig
}

func (c *inMemoryCache) CacheDnsResponse(question dns.Question, response models.DnsResponse) error {
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

	ret := c.cache.Set(key, value)

	if c.expireCallback != nil {
		go func(question dns.Question, response models.DnsResponse) {
			time.Sleep(response.GetTtl() - 10*time.Second)

			retrieveCount := 0
			var cached cacheEntry

			raw_value, err := c.cache.Get(getDnsQuestionCacheKey(question))
			if err == nil {
				err = json.Unmarshal(raw_value, &cached)
				if err == nil {
					retrieveCount = cached.RequestCount
				}
			}

			c.expireCallback(question, response, retrieveCount, c)
		}(question, response)
	}

	return ret
}

func (c *inMemoryCache) getDnsResponse(question dns.Question) (*models.DnsResponse, error) {
	timer := c.config.Metrics.GetCacheReadTimer()
	defer c.config.Metrics.ObserveTimer(timer)

	key := getDnsQuestionCacheKey(question)

	raw_value, err := c.cache.Get(key)

	if err == bigcache.ErrEntryNotFound {
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
		c.cache.Set(key, marshalled)
	}()

	return response, nil
}

func (c *inMemoryCache) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	c.config.Logger.Debug("attempting to resolve from cache", "qname", q.FirstQuestion().Name)

	if q.FirstQuestion() == nil {
		return nil, fmt.Errorf("query question was nil")
	}
	return c.getDnsResponse(*q.FirstQuestion())
}

func (c *inMemoryCache) SetExpireCallback(cb ExpireCallbackFn) {
	c.expireCallback = cb
}

func getInMemoryCache(keep bool, config CacheConfig) (Cache, error) {

	if keep && activeCache != nil {
		return activeCache, nil
	}

	if activeCache != nil {
		activeCache.cache.Close()
	}

	cache, err := bigcache.New(context.Background(), bigcache.DefaultConfig(120*time.Minute))

	if err != nil {
		return nil, err
	}

	activeCache = &inMemoryCache{cache: cache, config: config}

	return activeCache, nil
}
