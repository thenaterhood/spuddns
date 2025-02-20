package daemon

import (
	"github.com/thenaterhood/spuddns/app"
	"github.com/thenaterhood/spuddns/models"
)

type CachePipeline struct {
	quit   *chan bool
	config app.AppConfig
	state  *app.AppState
}

func NewCachePipeline(config app.AppConfig, state *app.AppState) *CachePipeline {
	quit := make(chan bool)
	return &CachePipeline{
		config: config,
		state:  state,
		quit:   &quit,
	}
}

func (c *CachePipeline) Stop() {
	*c.quit <- true
}

func (c *CachePipeline) Start() error {
	channel := make(chan models.DnsExchange, 300)
	c.state.DnsPipeline = &channel

	go func() {
		c.state.Log.Debug("cache pipeline started")

		for {
			select {
			case exchange := <-*c.state.DnsPipeline:
				if c.config.IsCacheable(exchange.Question, &exchange.Response) {
					c.state.Log.Debug("caching dns response", "query", exchange.Question.Name, "qtype", exchange.Question.Qtype)
					err := c.state.Cache.CacheDnsResponse(exchange.Question, exchange.Response)
					if err != nil {
						c.state.Log.Warn(
							"failed to cache dns exchange",
							"query", exchange.Question.Name,
							"qtype", exchange.Question.Qtype,
							"err", err,
						)
					}
				} else {
					c.state.Log.Debug("skipping cache for dns response", "query", exchange.Question.Name, "qtype", exchange.Question.Qtype)
				}
			case <-*c.quit:
				c.state.Log.Debug("cache pipeline stopped")
				return
			}
		}
	}()

	return nil
}
