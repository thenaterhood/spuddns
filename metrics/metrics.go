package metrics

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

type MetricsConfig struct {
	Enable bool
	Logger *slog.Logger
}

type MetricsInterface interface {
	IncQueriesAnswered()
	IncQueriesAnsweredFromCache()
	IncQueriesFailed()
	IncQueriesPredictivelyRefreshed()
	IncQueriesResilientlyRefreshed()
	GetCacheReadTimer() *prometheus.Timer
	GetForwardTimer() *prometheus.Timer
	GetResponseTimer() *prometheus.Timer
	ObserveTimer(*prometheus.Timer)
	Start() error
}

func GetMetrics(config MetricsConfig) MetricsInterface {
	if config.Enable {
		return newPrometheus(config)
	}
	return DummyMetrics{}
}
