package resolver

import (
	"time"

	"github.com/thenaterhood/spuddns/models"
)

// wraps a client to add behavior
type Middleware func(models.DnsQueryClient) models.DnsQueryClient

// add metrics timing
func withMetrics(config BaseResolverConfig) Middleware {
	return func(inner models.DnsQueryClient) models.DnsQueryClient {
		return &metricsWrapper{inner: inner, config: config}
	}
}

type metricsWrapper struct {
	inner  models.DnsQueryClient
	config BaseResolverConfig
}

func (w *metricsWrapper) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	timer := w.config.Metrics.GetForwardTimer()
	defer w.config.Metrics.ObserveTimer(timer)
	return w.inner.QueryDns(q)
}

// skip mDNS queries if forwarding is disabled
func withMdnsFilter(config BaseResolverConfig) Middleware {
	return func(inner models.DnsQueryClient) models.DnsQueryClient {
		return &mdnsFilterWrapper{inner: inner, config: config}
	}
}

type mdnsFilterWrapper struct {
	inner  models.DnsQueryClient
	config BaseResolverConfig
}

func (w *mdnsFilterWrapper) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	if q.IsMdns() && !w.config.Mdns.Forward {
		return nil, nil
	}
	return w.inner.QueryDns(q)
}

// enforce minimum TTL on responses
func withMinimumTtl(config BaseResolverConfig) Middleware {
	return func(inner models.DnsQueryClient) models.DnsQueryClient {
		return &minimumTtlWrapper{inner: inner, minTtl: time.Duration(config.ForceMimimumTtl) * time.Second}
	}
}

type minimumTtlWrapper struct {
	inner  models.DnsQueryClient
	minTtl time.Duration
}

func (w *minimumTtlWrapper) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	response, err := w.inner.QueryDns(q)

	if response != nil && response.IsSuccess() && !response.FromCache {
		if response.GetTtl() < w.minTtl {
			response.SetTtl(w.minTtl)
		}
	}

	return response, err
}

// applies multiple middlewares to a client (applied right-to-left)
func compose(client models.DnsQueryClient, middlewares ...Middleware) models.DnsQueryClient {
	for i := len(middlewares) - 1; i >= 0; i-- {
		client = middlewares[i](client)
	}
	return client
}
