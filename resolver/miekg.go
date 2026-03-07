package resolver

import (
	"log/slog"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

type miekgDnsClient struct {
	clientConfig BaseResolverConfig
	udpClient    dns.Client
	tcpClient    dns.Client
	logger       *slog.Logger
}

func NewMiekgDnsClient(config BaseResolverConfig) models.DnsQueryClient {
	inner := &miekgDnsClient{
		clientConfig: config,
		udpClient:    *newDnsClient("udp"),
		tcpClient:    *newDnsClient("tcp"),
		logger:       config.Logger,
	}
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

	var lastResponse *models.DnsResponse
	var lastErr error

	addr := formatAddr(mdc.clientConfig.Server)

	// Try UDP
	r, _, err := mdc.udpClient.Exchange(m, addr)
	lastResponse, lastErr = models.NewDnsResponseFromMsgAndErr(r, err)

	// Retry with TCP if truncated
	if lastResponse != nil && lastResponse.IsTruncated() {
		mdc.logger.Debug("response truncated, retrying with TCP", "server", mdc.clientConfig.Server)
		r, _, err = mdc.tcpClient.Exchange(m, addr)
		lastResponse, lastErr = models.NewDnsResponseFromMsgAndErr(r, err)
	}

	// Return on success
	if lastResponse != nil && lastResponse.IsSuccess() {
		lastResponse.Resolver = mdc.clientConfig.Server
		return lastResponse, lastErr
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
