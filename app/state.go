package app

import (
	"log/slog"

	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
)

type AppState struct {
	Cache            cache.Cache
	DefaultForwarder models.DnsQueryClient
	DnsPipeline      *chan models.DnsExchange
	Log              *slog.Logger
	Metrics          metrics.MetricsInterface
}
