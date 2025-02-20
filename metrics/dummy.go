package metrics

import "github.com/prometheus/client_golang/prometheus"

type DummyMetrics struct{}

func (ds DummyMetrics) IncQueriesAnswered()                  {}
func (ds DummyMetrics) IncQueriesAnsweredFromCache()         {}
func (ds DummyMetrics) IncQueriesFailed()                    {}
func (ds DummyMetrics) IncQueriesPredictivelyRefreshed()     {}
func (ds DummyMetrics) IncQueriesResilientlyRefreshed()      {}
func (ds DummyMetrics) GetCacheReadTimer() *prometheus.Timer { return nil }
func (ds DummyMetrics) GetForwardTimer() *prometheus.Timer   { return nil }
func (ds DummyMetrics) GetResponseTimer() *prometheus.Timer  { return nil }
func (ds DummyMetrics) Start() error                         { return nil }
func (ds DummyMetrics) ObserveTimer(_ *prometheus.Timer)     {}
