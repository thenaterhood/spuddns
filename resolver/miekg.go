package resolver

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

type miekgDnsClient struct {
	clientConfig DnsResolverConfig
}

func (mdc miekgDnsClient) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	if mdc.clientConfig.Mdns.QueryIsMdns(q) && !mdc.clientConfig.Mdns.Forward {
		return nil, nil
	}
	mdc.clientConfig.Logger.Debug("attempting to resolve query with standard dns")
	timer := mdc.clientConfig.Metrics.GetForwardTimer()
	defer mdc.clientConfig.Metrics.ObserveTimer(timer)
	c := new(dns.Client)
	c.DialTimeout = 5 * time.Second
	c.ReadTimeout = 5 * time.Second
	c.WriteTimeout = 5 * time.Second

	m := q.PreparedMsg()

	var r *dns.Msg
	var err error

	servers := mdc.clientConfig.Servers

	for _, server := range servers {
		r, _, err = c.Exchange(m, server+":53")

		if err != nil {
			mdc.clientConfig.Logger.Warn("dns lookup failed - will try next resolver", "server", server, "error", err)
			continue
		}

		if r != nil {
			mdc.clientConfig.Logger.Debug("dns lookup succeeded", "server", server, "result", fmt.Sprintf("%v", r.Answer))
			response, err := models.NewDnsResponseFromMsg(r)
			if response != nil {
				response.Resolver = server
			}

			return response, err
		}
	}

	if err != nil {
		return nil, err
	}

	return models.NewDnsResponseFromMsg(r)
}
