package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusMetrics struct {
	queriesAnswered             prometheus.Counter
	queriesAnsweredFromCache    prometheus.Counter
	queriesFailed               prometheus.Counter
	queriesPredictiveRefreshed  prometheus.Counter
	queriesResilientlyRefreshed prometheus.Counter
	queryResponseTime           prometheus.HistogramVec

	config MetricsConfig
}

func (ms PrometheusMetrics) IncQueriesAnswered() {
	ms.queriesAnswered.Inc()
}

func (ms PrometheusMetrics) IncQueriesAnsweredFromCache() {
	ms.queriesAnsweredFromCache.Inc()
}

func (ms PrometheusMetrics) IncQueriesFailed() {
	ms.queriesFailed.Inc()
}

func (ms PrometheusMetrics) IncQueriesPredictivelyRefreshed() {
	ms.queriesPredictiveRefreshed.Inc()
}

func (ms PrometheusMetrics) IncQueriesResilientlyRefreshed() {
	ms.queriesResilientlyRefreshed.Inc()
}

func (ms PrometheusMetrics) GetCacheReadTimer() *prometheus.Timer {
	return prometheus.NewTimer(ms.queryResponseTime.WithLabelValues("cache_read"))
}

func (ms PrometheusMetrics) GetForwardTimer() *prometheus.Timer {
	return prometheus.NewTimer(ms.queryResponseTime.WithLabelValues("forward"))
}

func (ms PrometheusMetrics) GetResponseTimer() *prometheus.Timer {
	return prometheus.NewTimer(ms.queryResponseTime.WithLabelValues("respond"))
}

func (ms PrometheusMetrics) ObserveTimer(timer *prometheus.Timer) {
	if timer != nil {
		timer.ObserveDuration()
	}
}

func (s PrometheusMetrics) Start() error {

	if s.config.Enable {
		go func() {
			s.config.Logger.Info("Starting prometheus metrics", "port", 2112, "endpoint", "/metrics")
			http.Handle("/metrics", promhttp.Handler())
			http.ListenAndServe(":2112", nil)
		}()
	}

	return nil
}

func newPrometheus(config MetricsConfig) PrometheusMetrics {
	return PrometheusMetrics{
		queriesAnswered: promauto.NewCounter(prometheus.CounterOpts{
			Name: "spuddns_queries_answered",
			Help: "The total number of queries answered since last start",
		}),
		queriesAnsweredFromCache: promauto.NewCounter(prometheus.CounterOpts{
			Name: "spuddns_queries_answered_from_cache",
			Help: "The total number of queries answered from the cache since last start",
		}),
		queryResponseTime: *promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:      "spuddns_duration_seconds",
			Help:      "Response time of DNS queries",
			Namespace: "spuddns",
		}, []string{"action"}),
		queriesFailed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "spuddns_queries_failed",
			Help: "The number of queries spuddns failed to resolve since last start",
		}),
		queriesPredictiveRefreshed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "spuddns_queries_predictive_refresh",
			Help: "The number of queries predictively refreshed on expiration",
		}),
		queriesResilientlyRefreshed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "spuddns_queries_resilient_refresh",
			Help: "The number of queries held in cache due to a resolution failure",
		}),
		config: config,
	}
}
