package main

import (
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"github.com/thenaterhood/spuddns/app"
	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/daemon"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/server"
	"github.com/thenaterhood/spuddns/system"
)

func dropPrivileges(uid, gid int) error {
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	return nil
}

func main() {
	conffile := "./spuddns.json"
	args := os.Args

	if len(args) > 1 {
		conffile = args[1]
	}

	config, err := app.GetConfig(conffile)
	if err != nil {
		fmt.Printf("config %s not loaded - starting with defaults: %v", conffile, err)
	}

	stdoutLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.Level(config.LogLevel),
	}))

	if len(config.UpstreamResolvers) < 1 {
		stdoutLogger.Warn("no upstream resolvers are configured!")
	}

	metrics := metrics.GetMetrics(metrics.MetricsConfig{
		Enable: !config.DisableMetrics,
		Logger: stdoutLogger,
	})

	cache, cacheErr := cache.GetCache(cache.CacheConfig{
		Logger:  stdoutLogger,
		Metrics: metrics,
		Enable:  !config.DisableCache,
	})
	if cacheErr != nil {
		stdoutLogger.Warn("failed to initialize cache - disabling caching", "err", cacheErr)
	}

	state := app.AppState{
		Cache:   cache,
		Log:     stdoutLogger,
		Metrics: metrics,
	}

	if !config.DisableCache {
		if config.PredictiveCache || config.ResilientCache {
			cacheMinder := daemon.NewCacheMinder(config, state)
			state.Cache.SetExpireCallback(cacheMinder.RefreshExpiringCacheItem)
		}
		cachePipeline := daemon.NewCachePipeline(*config, &state)
		cachePipelineCancel := cachePipeline.Start()
		defer cachePipelineCancel()
	}

	if config.RespectResolveConf {
		resolvconf, err := system.NewResolvConfFromPath(config.ResolvConfPath, state.Log)
		if err != nil {
			state.Log.Warn("failed to read resolvconf on start - will retry", "error", err)
		}

		if resolvconf != nil {
			config.ResolvConf = resolvconf
			resolvConfCancel := resolvconf.Watch()
			defer resolvConfCancel()
		}
	}

	config.EtcHosts = system.NewEtcHosts(state.Log)

	if config.PersistentCacheFile != "" {
		persistentCache := daemon.NewPersistentCache(*config, &state)
		persistentCacheCancel := persistentCache.Start()
		defer persistentCacheCancel()
	}

	metricsErr := state.Metrics.Start()
	if metricsErr != nil {
		state.Log.Warn("failed to start metrics", "err", metricsErr)
	}

	dnsServer := server.NewDnsServer(*config, state)
	dnsServer.Start()

	if err := dropPrivileges(65534, 65534); err != nil {
		state.Log.Warn("failed to drop privileges after initialization", "err", err)
	} else {
		state.Log.Debug("successfully dropped privileges after initialization")
	}

	select {}
}
