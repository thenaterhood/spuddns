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
}

func (c httpsClient) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	if q.IsMdns() && !c.clientConfig.Mdns.Forward {
		return nil, nil
	}

	timer := c.clientConfig.Metrics.GetForwardTimer()
	defer c.clientConfig.Metrics.ObserveTimer(timer)
	c.clientConfig.Logger.Debug("attempting to resolve query with dns over https")
	httpClient := http.Client{
		Timeout: time.Duration(c.clientConfig.Timeout) * time.Second,
	}

	query := q.PreparedMsg()

	packedQuery, err := query.Pack()
	if err != nil {
		return nil, err
	}

	for _, addr := range c.clientConfig.Servers {

		url, err := url.Parse(addr)
		if err != nil {
			c.clientConfig.Logger.Warn("unable to parse dns over https endpoint", "endpoint", addr)
			continue
		}

		if ip := net.ParseIP(url.Hostname()); ip == nil {
			if q.FirstQuestion().Name == url.Hostname()+"." {
				c.clientConfig.Logger.Warn("not using https resolver to resolve itself", "host", url.Host)
				continue
			}
		}

		request, err := http.NewRequest(http.MethodPost, addr, bytes.NewBuffer(packedQuery))
		if err != nil {
			c.clientConfig.Logger.Warn("failed to create request for http dns", "server", addr, "err", err)
			continue
		}
		request.Header.Set("Accept", models.ContentTypeDnsMessage)
		request.Header.Set("Content-Type", models.ContentTypeDnsMessage)

		resp, err := httpClient.Do(request)

		if err != nil {
			c.clientConfig.Logger.Warn("dns over https request failed", "server", addr, "err", err)
			continue
		}

		if resp == nil {
			c.clientConfig.Logger.Warn("dns over https request got no response", "server", addr)
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			c.clientConfig.Logger.Warn("not ok status for dns over https request", "server", addr, "status", resp.StatusCode)
			continue
		}

		msg, err := io.ReadAll(resp.Body)
		if err != nil {
			c.clientConfig.Logger.Warn("failed to read https dns response body", "server", addr, "err", err)
			continue
		}

		dnsResp, err := models.NewDnsResponseFromBytes(msg)
		if err != nil {
			c.clientConfig.Logger.Warn("failed to read https dns response", "server", addr, "err", err)
			continue
		}

		if dnsResp != nil {
			if dnsResp.IsSuccess() {
				dnsResp.Resolver = addr
				c.clientConfig.Logger.Debug("dns over https lookup succeeded", "server", addr)
			}
			return dnsResp, nil
		}
	}

	return models.NewNXDomainDnsResponse(), fmt.Errorf("https lookup failed")
}
