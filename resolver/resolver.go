package resolver

import (
	"log/slog"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
)

var clientCache *resolverCache

type resolverCache struct {
	cache      map[string]models.DnsQueryClient
	cacheMutex sync.RWMutex
}

func getResolverCache() *resolverCache {
	if clientCache == nil {
		clientCache = &resolverCache{
			cache:      map[string]models.DnsQueryClient{},
			cacheMutex: sync.RWMutex{},
		}
	}

	return clientCache
}

func (r *resolverCache) Get(config BaseResolverConfig) *models.DnsQueryClient {
	r.cacheMutex.RLock()
	defer r.cacheMutex.RUnlock()

	if client, ok := r.cache[config.Server]; ok {
		return &client
	}

	return nil
}

func (r *resolverCache) GetOrCreate(config BaseResolverConfig) models.DnsQueryClient {

	var client models.DnsQueryClient

	if client := r.Get(config); client != nil {
		return *client
	}

	if ip := net.ParseIP(config.Server); ip != nil {
		client = NewMiekgDnsClient(config)
	} else if _, err := url.Parse(config.Server); err == nil {
		client = NewHttpsClient(config)
	}

	if client != nil {
		r.cacheMutex.Lock()
		defer r.cacheMutex.Unlock()

		r.cache[config.Server] = client
	}

	return client
}

type BaseResolverConfig struct {
	Server          string
	Timeout         int
	Logger          *slog.Logger
	Metrics         metrics.MetricsInterface
	Mdns            *MdnsConfig
	ForceMimimumTtl int
}

type DnsResolverConfig struct {
	BaseResolverConfig
	Servers          []string
	Static           map[string]string
	Cache            models.DnsQueryClient
	DefaultForwarder models.DnsQueryClient
	Mdns             *MdnsConfig
}

type MdnsConfig struct {
	Enable  bool
	Forward bool
	Search  []string
}

func NewDefaultMdnsConfig() *MdnsConfig {
	return &MdnsConfig{
		Enable:  true,
		Forward: false,
	}
}

type multiClient struct {
	clients []models.DnsQueryClient
	config  DnsResolverConfig
}

func (mc *multiClient) QueryDns(query models.DnsQuery) (*models.DnsResponse, error) {
	for _, c := range mc.clients {
		response, err := c.QueryDns(query)

		if err != nil {
			continue
		}

		if response != nil && response.IsSuccess() {
			if !response.FromCache && response.GetTtl() < time.Duration(mc.config.ForceMimimumTtl)*time.Second {
				response.SetTtl(time.Duration(mc.config.ForceMimimumTtl) * time.Second)
			}
			return response, nil
		}
	}

	return models.NewNXDomainDnsResponse(), nil
}

func GetDnsResolver(clientConfig DnsResolverConfig) models.DnsQueryClient {
	if clientConfig.Timeout == 0 {
		clientConfig.Timeout = 2
	}

	if clientConfig.Mdns == nil {
		clientConfig.Mdns = NewDefaultMdnsConfig()
	}

	clients := []models.DnsQueryClient{
		&staticClient{clientConfig},
	}

	if clientConfig.Cache != nil {
		clients = append(clients, clientConfig.Cache)
	}

	if clientConfig.Mdns.Enable {
		clients = append(clients, NewMdnsClient(clientConfig.BaseResolverConfig))
	}

	cache := getResolverCache()

	for _, resolver := range clientConfig.Servers {
		config := clientConfig
		config.Server = resolver

		if client := cache.GetOrCreate(config.BaseResolverConfig); client != nil {
			clients = append(clients, client)
		}
	}

	if clientConfig.DefaultForwarder != nil {
		clients = append(clients, clientConfig.DefaultForwarder)
	}

	return &multiClient{
		clients,
		clientConfig,
	}
}
