package resolver

import (
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

type miekgDnsClient struct {
	clientConfig DnsResolverConfig
}

func NewMiekgDnsClient(config DnsResolverConfig) models.DnsQueryClient {
	inner := &miekgDnsClient{clientConfig: config}
	// Apply middlewares: metrics, mDNS filter, TTL
	return compose(
		inner,
		withMetrics(config),
		withMdnsFilter(config),
		withMinimumTtl(config),
	)
}

func (mdc *miekgDnsClient) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	m := q.PreparedMsg()
	udpClient := newDnsClient("udp")
	tcpClient := newDnsClient("tcp")

	var lastResponse *models.DnsResponse
	var lastErr error

	for _, server := range mdc.clientConfig.Servers {
		addr := formatAddr(server)

		// Try UDP
		r, _, err := udpClient.Exchange(m, addr)
		lastResponse, lastErr = models.NewDnsResponseFromMsgAndErr(r, err)

		// Retry with TCP if truncated
		if lastResponse != nil && lastResponse.IsTruncated() {
			mdc.clientConfig.Logger.Debug("response truncated, retrying with TCP", "server", server)
			r, _, err = tcpClient.Exchange(m, addr)
			lastResponse, lastErr = models.NewDnsResponseFromMsgAndErr(r, err)
		}

		// Return on success
		if lastResponse != nil && lastResponse.IsSuccess() {
			lastResponse.Resolver = server
			return lastResponse, lastErr
		}
	}

	// Return last response instead of potentially nil
	if lastResponse != nil {
		return lastResponse, lastErr
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return models.NewDnsResponseFromMsg(nil)
}

func newDnsClient(network string) *dns.Client {
	return &dns.Client{
		Net:          network,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
}

func formatAddr(server string) string {
	if _, _, err := net.SplitHostPort(server); err != nil {
		return net.JoinHostPort(server, "53")
	}
	return server
}
