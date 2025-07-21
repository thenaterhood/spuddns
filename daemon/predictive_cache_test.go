package daemon

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/app"
	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
	"github.com/thenaterhood/spuddns/resolver"
)

func getAppState(cache cache.Cache) *app.AppState {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.Level(slog.LevelDebug),
	}))
	return &app.AppState{
		Cache:   cache,
		Metrics: &metrics.DummyMetrics{},
		Log:     log,
		DefaultForwarder: resolver.GetDnsResolver(resolver.DnsResolverConfig{
			Logger:  log,
			Servers: []string{},
			Static: map[string]string{
				"example.com": "203.0.113.1",
				"google.com":  "203.0.113.2",
			},
			Cache: cache,
		}),
	}
}

func waitForConsistency(cache cache.Cache, q dns.Question) (*models.DnsResponse, error) {
	// this is jank
	dnsQuery, _ := models.NewDnsQueryFromQuestions([]dns.Question{q})
	resp, err := cache.QueryDns(*dnsQuery)
	waited := 0

	for resp == nil && err == nil && waited < 1000 {
		resp, err = cache.QueryDns(*dnsQuery)
		time.Sleep(10 * time.Nanosecond)
		waited += 1
	}

	return resp, err
}

func TestRefreshExpiringCacheItem(t *testing.T) {
	cache, err := cache.GetCache(cache.CacheConfig{
		Enable:  true,
		Metrics: &metrics.DummyMetrics{},
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.Level(slog.LevelDebug),
		})),
	})

	if err != nil {
		t.Fatalf("failed to get cache: %v", err)
	}

	appCfg := app.GetDefaultConfig()
	appCfg.PredictiveThreshold = 2

	q := dns.Question{Name: "example.com."}
	answer, err := models.NewDnsResponseFromDnsAnswers(
		[]models.DNSAnswer{
			{
				Name: "example.com.",
				TTL:  10,
				Data: "203.0.113.1",
				Type: dns.TypeA,
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
	}
	if answer == nil {
		t.Fatal("hardcoded dns response was unexectedly nil")
	}

	state := getAppState(cache)
	cachePipeline := NewCachePipeline(appCfg, state)
	cachePipelineCancel := cachePipeline.Start()
	defer cachePipelineCancel()

	minder := NewCacheMinder(&appCfg, *state)
	minder.RefreshExpiringCacheItem(q, *answer, 0, cache)

	resp, err := waitForConsistency(cache, q)
	if err != nil {
		t.Errorf("unexpected error checking for refreshed unused item (should not be refreshed): %v", err)
	}
	if resp != nil {
		t.Errorf("unused cache item was refreshed, should not have been")
	}

	minder.RefreshExpiringCacheItem(q, *answer, 1, cache)
	resp, err = waitForConsistency(cache, q)
	if err != nil {
		t.Errorf("unexpected error checking for refreshed infrequent item (should not be refreshed): %v", err)
	}
	if resp != nil {
		t.Errorf("infrequently used item was refreshed, should not have been")
	}

	minder.RefreshExpiringCacheItem(q, *answer, 5, cache)
	resp, err = waitForConsistency(cache, q)
	if err != nil {
		t.Errorf("unexpected error checking for refreshed item (should be refreshed): %v", err)
	}
	if resp == nil {
		t.Fatalf("frequently used cache item was not refreshed")
	}

	answers, err := resp.Answers()
	if err != nil {
		t.Errorf("unexpected error getting answers: %v", err)
	}

	if answers == nil {
		t.Fatalf("answers were nil")
	}

	expectedAnswers, _ := answer.Answers()
	if resp != nil && !resp.IsEmpty() && answers[0].Data != expectedAnswers[0].Data {
		t.Errorf("frequently used cache item was not correctly refreshed expected = %v, actual = %v", answer, resp)
	}
}
