package resolver

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/thenaterhood/spuddns/models"
)

type httpsClient struct {
	clientConfig DnsResolverConfig
	httpClient   *http.Client
}

func NewHttpsClient(config DnsResolverConfig) models.DnsQueryClient {
	timeout := time.Duration(config.Timeout) * time.Second

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 5,
		},
		Timeout: timeout,
	}
	inner := &httpsClient{
		clientConfig: config,
		httpClient:   client,
	}
	// Apply middlewares: metrics, mDNS filter, TTL
	return compose(
		inner,
		withMetrics(config),
		withMdnsFilter(config),
		withMinimumTtl(config),
	)
}

func (c *httpsClient) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	query := q.PreparedMsg()

	packedQuery, err := query.Pack()
	if err != nil {
		return nil, err
	}

	for _, addr := range c.clientConfig.Servers {
		if response := c.queryServer(addr, packedQuery, q); response != nil {
			return response, nil
		}
	}

	return models.NewNXDomainDnsResponse(), fmt.Errorf("https lookup failed")
}

func (c *httpsClient) queryServer(addr string, packedQuery []byte, q models.DnsQuery) *models.DnsResponse {
	// Validate URL
	parsedURL, err := url.Parse(addr)
	if err != nil {
		c.clientConfig.Logger.Warn("unable to parse dns over https endpoint", "endpoint", addr)
		return nil
	}

	// Prevent self-resolution
	if ip := net.ParseIP(parsedURL.Hostname()); ip == nil {
		if q.FirstQuestion().Name == parsedURL.Hostname()+"." {
			c.clientConfig.Logger.Warn("not using https resolver to resolve itself", "host", parsedURL.Host)
			return nil
		}
	}

	// Make request
	request, err := http.NewRequest(http.MethodPost, addr, bytes.NewBuffer(packedQuery))
	if err != nil {
		c.clientConfig.Logger.Warn("failed to create request for http dns", "server", addr, "err", err)
		return nil
	}
	request.Header.Set("Accept", models.ContentTypeDnsMessage)
	request.Header.Set("Content-Type", models.ContentTypeDnsMessage)

	resp, err := c.httpClient.Do(request)
	if err != nil {
		c.clientConfig.Logger.Warn("dns over https request failed", "server", addr, "err", err)
		return nil
	}

	if resp == nil {
		c.clientConfig.Logger.Warn("dns over https request got no response", "server", addr)
		return nil
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.clientConfig.Logger.Warn("not ok status for dns over https request", "server", addr, "status", resp.StatusCode)
		return nil
	}

	msg, err := io.ReadAll(resp.Body)
	if err != nil {
		c.clientConfig.Logger.Warn("failed to read https dns response body", "server", addr, "err", err)
		return nil
	}

	dnsResp, err := models.NewDnsResponseFromBytes(msg)
	if err != nil {
		c.clientConfig.Logger.Warn("failed to read https dns response", "server", addr, "err", err)
		return nil
	}

	if dnsResp != nil && dnsResp.IsSuccess() {
		dnsResp.Resolver = addr
		c.clientConfig.Logger.Debug("dns over https lookup succeeded", "server", addr)
	}

	return dnsResp
}
