package daemon

import (
	"context"
	"time"

	"github.com/thenaterhood/spuddns/app"
)

type PersistentCache struct {
	config app.AppConfig
	state  *app.AppState
}

func NewPersistentCache(config app.AppConfig, state *app.AppState) *PersistentCache {
	return &PersistentCache{
		config: config,
		state:  state,
	}
}

func (c *PersistentCache) Start() context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c.state.Log.Debug("persistent cache started")
		if err := c.state.Cache.Load(c.config.PersistentCacheFile); err != nil {
			c.state.Log.Warn("failed to load cache", "error", err)
		}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				c.state.Log.Debug("cache pipeline stopped")
				return
			case <-ticker.C:
				c.state.Log.Debug("persisting cache to disk")
				err := c.state.Cache.Persist(c.config.PersistentCacheFile)
				if err != nil {
					c.state.Log.Warn("failed to persist cache", "error", err)
				}
			}
		}
	}()
	return cancel
}
