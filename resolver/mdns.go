package resolver

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

type mdnsClient struct {
	clientConfig DnsResolverConfig
}

func (c mdnsClient) QueryDns(q models.DnsQuery) (*models.DnsResponse, error) {
	if !c.clientConfig.Mdns.Enable {
		return nil, nil
	}

	if !c.clientConfig.Mdns.QueryIsMdns(q) {
		return nil, nil
	}

	c.clientConfig.Logger.Debug("attemping to resolve query with mDNS", "qname", q.FirstQuestion().Name)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		c.clientConfig.Logger.Warn("failed to listen UDP for mDNS", "error", err)
		return nil, err
	}
	defer conn.Close()

	timeout := time.Duration(c.clientConfig.Timeout) * time.Second

	query := q.PreparedMsg()
	packed, err := query.Pack()
	if err != nil {
		return nil, err
	}

	multicastAddr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		c.clientConfig.Logger.Warn("failed to resolve mDNS address", "error", err)
		return nil, err
	}

	_, err = conn.WriteToUDP(packed, multicastAddr)
	if err != nil {
		c.clientConfig.Logger.Warn("failed to send mDNS request", "error", err)
		return nil, err
	}

	// Collect responses
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	buffer := make([]byte, 1500)

	for {
		select {
		case <-ctx.Done():
			return models.NewNXDomainDnsResponse(), nil

		default:
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			n, from, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				continue
			}

			c.clientConfig.Logger.Debug("received mDNS data from", "addr", from)

			response, err := parseResponse(buffer[:n], q)
			if err != nil {
				c.clientConfig.Logger.Warn("error parsing mDNS response", "error", err)
				return models.NewServFailDnsResponse(), err
			}

			if response != nil {
				answers, err := response.Answers()
				if err == nil && answers != nil {
					return response, nil
				}
			}
		}
	}
}

func parseResponse(data []byte, query models.DnsQuery) (*models.DnsResponse, error) {
	var msg dns.Msg
	if err := msg.Unpack(data); err != nil {
		return nil, err
	}

	if !msg.MsgHdr.Response {
		return nil, nil
	}

	if msg.MsgHdr.Id != query.PreparedMsg().Id {
		return nil, nil
	}

	return models.NewDnsResponseFromMsg(&msg)
}
