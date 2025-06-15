package cache

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
)

type ExpireCallbackFn func(question dns.Question, response models.DnsResponse, retrieveCount int, cache Cache)

type CacheConfig struct {
	Enable  bool
	Logger  *slog.Logger
	Metrics metrics.MetricsInterface
}

type Cache interface {
	CacheDnsResponse(dns.Question, models.DnsResponse) error
	SetExpireCallback(cb ExpireCallbackFn)
	QueryDns(models.DnsQuery) (*models.DnsResponse, error)
}

type cacheEntry struct {
	Dns          []models.DNSAnswer
	Expires      time.Time
	RequestCount int
	Resolver     string
}

func getDnsQuestionCacheKey(question dns.Question) string {
	return fmt.Sprintf("%s::%d", question.Name, question.Qtype)
}

func GetCache(config CacheConfig) (Cache, error) {
	if config.Enable {
		cache, err := getInMemoryCache(false, config)
		if err != nil {
			return &DummyCache{}, err
		}
		return cache, err
	}
	return &DummyCache{}, nil
}
