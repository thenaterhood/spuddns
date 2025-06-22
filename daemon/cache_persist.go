package daemon

import (
	"time"

	"github.com/thenaterhood/spuddns/app"
)

type PersistentCache struct {
	quit   *chan bool
	config app.AppConfig
	state  *app.AppState
}

func NewPersistentCache(config app.AppConfig, state *app.AppState) *PersistentCache {
	quit := make(chan bool)
	return &PersistentCache{
		config: config,
		state:  state,
		quit:   &quit,
	}
}

func (c *PersistentCache) Stop() {
	*c.quit <- true
}

func (c *PersistentCache) Start() error {
	go func() {
		c.state.Log.Debug("persistent cache started")

		if err := c.state.Cache.Load(c.config.PersistentCacheFile); err != nil {
			c.state.Log.Warn("failed to load cache", "error", err)
		}

		for {
			select {
			case <-*c.quit:
				c.state.Log.Debug("cache pipeline stopped")
				return
			default:
				c.state.Log.Debug("persisting cache to disk")
				err := c.state.Cache.Persist(c.config.PersistentCacheFile)
				if err != nil {
					c.state.Log.Warn("failed to persist cache", "error", err)
				}
				time.Sleep(30 * time.Second)
			}
		}
	}()

	return nil
}
