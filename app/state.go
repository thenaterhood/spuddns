package app

import (
	"log/slog"

	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
	"github.com/thenaterhood/spuddns/resolver"
)

type AppState struct {
	Cache            cache.Cache
	DefaultForwarder resolver.DnsResolver
	DnsPipeline      *chan models.DnsExchange
	Log              *slog.Logger
	Metrics          metrics.MetricsInterface
}
