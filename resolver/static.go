package resolver

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

const StaticTTL uint32 = 10

type staticClient struct {
	clientConfig DnsResolverConfig
}

func (c staticClient) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	query := q.FirstQuestion()
	c.clientConfig.Logger.Debug("attempting to resolve query with static record from config")

	if c.clientConfig.Static == nil {
		c.clientConfig.Logger.Debug("static entries are not configured")
		return models.NewNXDomainDnsResponse(), nil
	}

	for _, name := range []string{query.Name[0 : len(query.Name)-1], query.Name} {

		ip, ok := c.clientConfig.Static[name]
		if ok {
			ipAddr := net.ParseIP(ip)
			if ipAddr == nil {
				return nil, fmt.Errorf("static entry '%s' was not a valid address", ip)
			}
			dnsType := dns.TypeAAAA
			if ipAddr.To4() != nil {
				dnsType = dns.TypeA
			}

			c.clientConfig.Logger.Debug("resolved from static", "qname", query.Name)

			return models.NewDnsResponseFromDnsAnswers(
				[]models.DNSAnswer{
					{
						Name: query.Name,
						Type: dnsType,
						TTL:  30 * time.Second,
						Data: ip,
					},
				},
			)
		}
	}

	return models.NewNXDomainDnsResponse(), &dns.Error{}
}
