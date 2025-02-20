package resolver

import (
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
)

type DnsResolverConfig struct {
	Servers         []string
	Logger          *slog.Logger
	Timeout         int
	Metrics         metrics.MetricsInterface
	Static          map[string]string
	ForceMimimumTtl int
}

type DnsResolver interface {
	QueryDns(q models.DnsQuery) (*models.DnsResponse, error)
}

type multiClient struct {
	clients []DnsResolver
	config  DnsResolverConfig
}

func (mc *multiClient) QueryDns(query models.DnsQuery) (*models.DnsResponse, error) {

	for _, c := range mc.clients {
		response, err := c.QueryDns(query)

		if err != nil {
			continue
		}

		if response != nil {
			if response.IsSuccess() {
				if !response.FromCache && response.GetTtl() < time.Duration(mc.config.ForceMimimumTtl)*time.Second {
					response.SetTtl(time.Duration(mc.config.ForceMimimumTtl) * time.Second)
				}
				return response, nil
			}
		}
	}

	return models.NewNXDomainDnsResponse(), nil
}

func GetDnsResolver(clientConfig DnsResolverConfig, dnsCache models.DnsQueryClient) DnsResolver {
	staticDnsClient := staticClient{clientConfig}

	clients := []DnsResolver{
		staticDnsClient,
	}

	if dnsCache != nil {
		clients = append(clients, dnsCache)
	}

	for _, resolver := range clientConfig.Servers {
		config := clientConfig

		if ip := net.ParseIP(resolver); ip != nil {
			config.Servers = []string{resolver}
			clients = append(clients, miekgDnsClient{
				config,
			})
		} else if _, err := url.Parse(resolver); err == nil {
			config.Servers = []string{resolver}
			clients = append(clients, httpsClient{
				config,
			})
		}
	}

	return &multiClient{
		clients,
		clientConfig,
	}
}
