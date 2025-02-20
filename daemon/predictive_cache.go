package daemon

import (
	"math/rand/v2"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/app"
	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/models"
	"github.com/thenaterhood/spuddns/resolver"
)

type CacheMinder struct {
	appState  app.AppState
	appConfig *app.AppConfig
}

func NewCacheMinder(config *app.AppConfig, state app.AppState) *CacheMinder {
	return &CacheMinder{
		appState:  state,
		appConfig: config,
	}
}

func (minder CacheMinder) RefreshExpiringCacheItem(q dns.Question, expiring models.DnsResponse, retrieveCount int, c cache.Cache) {

	minder.appState.Log.Debug("cache entry expiring", "query", q.Name, "qtype", q.Qtype, "retrievalCount", retrieveCount)

	if retrieveCount < minder.appConfig.PredictiveThreshold {
		return
	}

	minder.appState.Log.Debug("refreshing frequent cache item", "query", q.Name, "qtype", q.Qtype)

	query, err := models.NewDnsQueryFromQuestions([]dns.Question{q})
	if err != nil {
		minder.appState.Log.Warn("invalid dns query", "err", err)
		return
	}

	forwarder := minder.appState.DefaultForwarder
	if forwarder == nil {
		servers := []string{}

		if expiring.Resolver != "" {
			servers = append(servers, expiring.Resolver)
		}

		servers = append(servers, minder.appConfig.GetUpstreamResolvers(q.Name)...)
		resolverConfig := resolver.DnsResolverConfig{
			Servers: servers,
			Metrics: minder.appState.Metrics,
			Logger:  minder.appState.Log,
		}

		forwarder = resolver.GetDnsResolver(resolverConfig, nil)
	}

	response, err := forwarder.QueryDns(*query)
	if err != nil {
		minder.appState.Log.Warn("failed to re-run common query", "query", q.Name, "error", err)
	}

	if response == nil && minder.appConfig.ResilientCache {
		minder.appState.Log.Warn("re-caching last value (resilient cache)", "query", q.Name, "qtype", q.Qtype)
		minder.appState.Metrics.IncQueriesResilientlyRefreshed()
		response = &expiring
	} else {
		minder.appState.Metrics.IncQueriesPredictivelyRefreshed()
	}

	if response != nil {
		// Finangle the TTL so that any upstream caching doesn't cause us to
		// cache a DNS value that will immediately expire.
		// This is jank.
		maxTtlMinutes := 5
		minTtlMinutes := 3
		newTtl := uint64(rand.IntN(maxTtlMinutes+1-minTtlMinutes)+minTtlMinutes) * uint64(time.Minute)
		response.SetTtl(max(response.GetTtl(), time.Duration(newTtl)))

		// This does not preserve the retrieval count. This is deliberate so that
		// a stale item will eventually fall out of the cache. This might need to be
		// revisited because a semi-active item that doesn't see enough queries in the
		// TTL won't stay populated in the cache.
		if minder.appState.DnsPipeline != nil {
			minder.appState.Log.Debug("re-cached common query", "query", q.Name, "ttl", response.GetTtl())
			*minder.appState.DnsPipeline <- models.DnsExchange{Question: q, Response: *response}
		}
	} else {
		minder.appState.Log.Warn("got nil dns response", "query", q.Name)
	}
}
