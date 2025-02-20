package models

import (
	"github.com/miekg/dns"
)

type DnsQueryClient interface {
	QueryDns(DnsQuery) (*DnsResponse, error)
}

const EDNS0CpeIdOptionCode uint16 = 65074
const ContentTypeDnsMessage string = "application/dns-message"
const ContentTypeJson string = "application/json"

type DnsExchange struct {
	Question dns.Question
	Response DnsResponse
}
