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
	var lastErr error
	var lastResponse *models.DnsResponse

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

		r, _, lastErr = udpClient.Exchange(m, addr)

		response, err := models.NewDnsResponseFromMsgAndErr(r, lastErr)

		if response != nil && response.IsTruncated() {
			mdc.clientConfig.Logger.Debug("oversized dns exchange; retrying over tcp", "server", server, "err", lastErr)
			r, _, lastErr = tcpClient.Exchange(m, addr)
			response, err = models.NewDnsResponseFromMsgAndErr(r, lastErr)
		}

		if response != nil && response.IsSuccess() {
			mdc.clientConfig.Logger.Debug("dns lookup succeeded", "server", server, "result", fmt.Sprintf("%v", r.Answer))
			response.Resolver = server
			return response, err
		}

		// Store the last response in case we need to fall back
		if response != nil {
			lastResponse = response
		}
	}

	// Return the last response if we have one, even if it's not a success
	if lastResponse != nil {
		return lastResponse, lastErr
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return models.NewDnsResponseFromMsg(r)
}
