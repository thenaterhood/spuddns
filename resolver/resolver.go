package resolver

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
)

type DnsResolverConfig struct {
	Servers          []string
	Logger           *slog.Logger
	Timeout          int
	Metrics          metrics.MetricsInterface
	Static           map[string]string
	ForceMimimumTtl  int
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

func (m *MdnsConfig) QueryIsMdns(q models.DnsQuery) bool {
	qname := q.FirstQuestion().Name

	fmt.Printf("%s - isMdns = %v\n", qname, strings.HasSuffix(qname, ".local."))

	return strings.HasSuffix(qname, ".local.")
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

func GetDnsResolver(clientConfig DnsResolverConfig) models.DnsQueryClient {
	if clientConfig.Timeout == 0 {
		clientConfig.Timeout = 2
	}

	if clientConfig.Mdns == nil {
		clientConfig.Mdns = NewDefaultMdnsConfig()
	}

	staticDnsClient := staticClient{clientConfig}

	clients := []models.DnsQueryClient{
		staticDnsClient,
	}

	if clientConfig.Cache != nil {
		clients = append(clients, clientConfig.Cache)
	}

	clients = append(clients, mdnsClient{clientConfig})

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

	if clientConfig.DefaultForwarder != nil {
		clients = append(clients, clientConfig.DefaultForwarder)
	}

	return &multiClient{
		clients,
		clientConfig,
	}
}
