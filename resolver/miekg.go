package resolver

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

type miekgDnsClient struct {
	clientConfig DnsResolverConfig
}

func (mdc miekgDnsClient) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	if q.IsMdns() && !mdc.clientConfig.Mdns.Forward {
		return nil, nil
	}
	mdc.clientConfig.Logger.Debug("attempting to resolve query with standard dns")
	timer := mdc.clientConfig.Metrics.GetForwardTimer()
	defer mdc.clientConfig.Metrics.ObserveTimer(timer)

	m := q.PreparedMsg()

	var r *dns.Msg
	var err error

	servers := mdc.clientConfig.Servers

	udpClient := &dns.Client{
		Net:          "udp",
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	tcpClient := &dns.Client{
		Net:          "tcp",
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	for _, server := range servers {

		addr := server
		if _, _, perr := net.SplitHostPort(server); perr != nil {
			// server did not include a port, default to 53
			addr = net.JoinHostPort(server, "53")
		}

		r, _, err = udpClient.Exchange(m, addr)

		response, err := models.NewDnsResponseFromMsgAndErr(r, err)

		if response != nil {
			if response.IsTruncated() {
				mdc.clientConfig.Logger.Debug("oversized dns exchange; retrying over tcp", "server", server, "err", err)
				r, _, err = tcpClient.Exchange(m, addr)
				response, err = models.NewDnsResponseFromMsgAndErr(r, err)
			}

			if response != nil && response.IsSuccess() {
				mdc.clientConfig.Logger.Debug("dns lookup succeeded", "server", server, "result", fmt.Sprintf("%v", r.Answer))
				response.Resolver = server
				return response, err
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return models.NewDnsResponseFromMsg(r)
}
