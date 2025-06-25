package cache

import (
	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

type DummyCache struct{}

func (c *DummyCache) CacheDnsResponse(dns.Question, models.DnsResponse) error  { return nil }
func (c *DummyCache) GetDnsResponse(dns.Question) (*models.DnsResponse, error) { return nil, nil }
func (c *DummyCache) SetExpireCallback(ExpireCallbackFn)                       {}
func (c *DummyCache) QueryDns(models.DnsQuery) (*models.DnsResponse, error)    { return nil, nil }
func (c *DummyCache) Persist(string) error                                     { return nil }
func (c *DummyCache) Load(string) error                                        { return nil }
