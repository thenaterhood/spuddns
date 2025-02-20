package cache

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
)

func getCacheConfig() CacheConfig {

	return CacheConfig{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.Level(slog.LevelDebug),
		})),
		Metrics: metrics.DummyMetrics{},
	}
}

func TestGetCache(t *testing.T) {
	cache, _ := getInMemoryCache(false, getCacheConfig())

	if cache == nil {
		t.Errorf("cache was unexpectedly nil")
	}
}

func TestCacheSet(t *testing.T) {
	cache, _ := getInMemoryCache(false, getCacheConfig())

	if cache == nil {
		t.Errorf("cache was unexpectedly nil")
	}

	question := dns.Question{
		Name:   "example.com.",
		Qtype:  1,
		Qclass: 0,
	}

	response, err := models.NewDnsResponseFromDnsAnswers(
		[]models.DNSAnswer{
			{
				Name: "example.com.",
				Type: 1,
				TTL:  30 * time.Second,
				Data: "0.0.0.0",
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
	}

	err = cache.CacheDnsResponse(question, *response)
	if err != nil {
		t.Errorf("cache set errored: %s", err)
	}

	cache, _ = getInMemoryCache(true, getCacheConfig())

	if cache == nil {
		t.Errorf("failed to get cache again")
	}

	cachedValue, err := cache.GetDnsResponse(question)
	if err != nil {
		t.Errorf("cache retrieve error: %s", err)
	}

	if cachedValue == nil {
		t.Errorf("failed to get cached value")
	}
}

func TestCacheExpires(t *testing.T) {
	cache, _ := getInMemoryCache(false, getCacheConfig())

	if cache == nil {
		t.Errorf("cache was unexpectedly nil")
	}

	question := dns.Question{
		Name:   "example.com.",
		Qtype:  1,
		Qclass: 0,
	}

	response, err := models.NewDnsResponseFromDnsAnswers(
		[]models.DNSAnswer{
			{
				Name: "example.com.",
				Type: 1,
				TTL:  0,
				Data: "0.0.0.0",
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
	}

	err = cache.CacheDnsResponse(question, *response)
	if err != nil {
		t.Errorf("cache set errored: %s", err)
	}

	cache, _ = getInMemoryCache(true, getCacheConfig())

	if cache == nil {
		t.Errorf("failed to get cache again")
	}

	cachedValue, err := cache.GetDnsResponse(question)
	if err != nil {
		t.Errorf("cache retrieve error: %s", err)
	}

	if cachedValue != nil {
		t.Errorf("cached value should have expired")
	}
}

func TestCacheNotKept(t *testing.T) {
	cache, _ := getInMemoryCache(false, getCacheConfig())

	if cache == nil {
		t.Errorf("cache was unexpectedly nil")
	}

	question := dns.Question{
		Name:   "example.com.",
		Qtype:  1,
		Qclass: 0,
	}

	response, err := models.NewDnsResponseFromDnsAnswers(
		[]models.DNSAnswer{
			{
				Name: "example.com.",
				Type: 1,
				TTL:  0,
				Data: "0.0.0.0",
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
	}

	err = cache.CacheDnsResponse(question, *response)
	if err != nil {
		t.Errorf("cache set errored: %s", err)
	}

	cache, _ = getInMemoryCache(false, getCacheConfig())

	if cache == nil {
		t.Errorf("failed to get cache again")
	}

	cachedValue, err := cache.GetDnsResponse(question)
	if err != nil {
		t.Errorf("cache retrieve error: %s", err)
	}

	if cachedValue != nil {
		t.Errorf("cached value should not exist")
	}
}

func TestCacheDoesNotReturnMangledEntry(t *testing.T) {
	cache, _ := getInMemoryCache(false, getCacheConfig())

	if cache == nil {
		t.Errorf("cache was unexpectedly nil")
	}

	question := dns.Question{
		Name:   "example.com.",
		Qtype:  1,
		Qclass: 0,
	}

	response, err := models.NewDnsResponseFromDnsAnswers(
		[]models.DNSAnswer{
			{
				Name: "example.com.",
				Type: 1,
				TTL:  30 * time.Second,
				Data: "0.0.0.0",
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
	}

	err = cache.CacheDnsResponse(question, *response)
	if err != nil {
		t.Errorf("cache set errored: %s", err)
	}

	raw_cache := activeCache.cache
	raw_cache.Set(getDnsQuestionCacheKey(question), []byte("asdf"))

	if cache == nil {
		t.Errorf("failed to get cache again")
	}

	cachedValue, err := cache.GetDnsResponse(question)
	if err == nil {
		t.Errorf("cache retrieve should have failed")
	}

	if cachedValue != nil {
		t.Errorf("got a mangled cache value")
	}
}

func TestCacheEmptyDnsResponseDoesNotCrash(t *testing.T) {
	cache, _ := getInMemoryCache(false, getCacheConfig())

	if cache == nil {
		t.Errorf("cache was unexpectedly nil")
	}

	question := dns.Question{
		Name:   "example.com.",
		Qtype:  1,
		Qclass: 0,
	}

	response, err := models.NewDnsResponseFromDnsAnswers([]models.DNSAnswer{})
	if err != nil {
		t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
	}

	err = cache.CacheDnsResponse(question, *response)
	if err != nil {
		t.Errorf("cache set errored: %s", err)
	}

	cachedValue, err := cache.GetDnsResponse(question)
	if err != nil {
		t.Errorf("cache retrieve should not have failed")
	}

	if cachedValue != nil {
		t.Errorf("got a empty/invalid cache value")
	}
}
