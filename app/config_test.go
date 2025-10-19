package app

import (
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

func TestGetConfig(t *testing.T) {
	config, _ := GetConfig("./spuddns.json")

	if config == nil {
		t.Errorf("cache was unexpectedly nil")
	}
}

func TestStrToIpNet(t *testing.T) {
	testCases := map[string]*net.IPNet{
		"example.com": nil,
		"127.0.0.1": {
			IP:   net.ParseIP("127.0.0.1"),
			Mask: net.CIDRMask(32, 32),
		},
		"127.0.0.1/32": {
			IP:   net.ParseIP("127.0.0.1"),
			Mask: net.CIDRMask(32, 32),
		},
		"127.0.0.0/16": {
			IP:   net.ParseIP("127.0.0.0"),
			Mask: net.CIDRMask(16, 32),
		},
		"127.0.0.0/64": nil, // invalid IP
		"::": {
			IP:   net.ParseIP("::"),
			Mask: net.CIDRMask(128, 128),
		},
	}

	for input, expected := range testCases {
		testName := fmt.Sprintf("str_to_ipnet(%s) = %s", input, expected)

		t.Run(testName, func(t *testing.T) {
			output := strToIpNet(input)
			if expected.String() != output.String() {
				t.Errorf("str_to_ipnet(%s) actual = %d, expected = %s", input, output, expected)
			}
		})
	}
}

func TestIsCacheableDnsQueryBadDataDoesNotCrash(t *testing.T) {
	appConfig := AppConfig{
		DoNotCache: []string{},
	}
	appConfig.prepare()

	q := dns.Question{
		Name:   "example.com.",
		Qtype:  4,
		Qclass: 1,
	}

	dnsResponse, err := models.NewDnsResponseFromDnsAnswers(
		[]models.DNSAnswer{
			{
				Name: "example.com.",
				Type: dns.TypeA,
				TTL:  1,
				Data: "asdfasdf", // invalid IP
			},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
	}

	cacheable := appConfig.IsCacheable(q, dnsResponse)
	if cacheable {
		t.Errorf("expected IsCacheable to be false for invalid DNS response")
	}
}

func TestIsCacheableDnsQuery(t *testing.T) {
	appConfig := AppConfig{
		DoNotCache: []string{"127.0.0.1", "example.com", "*.google.com", "127.0.0.1/24"},
	}
	appConfig.prepare()

	testCases := map[string]bool{
		"rit.edu.":                      true,
		"se.rit.edu.":                   true,
		"cs.rit.edu.":                   true,
		"example.com.":                  false,
		"search.google.com.":            false,
		"connectivitycheck.google.com.": false,
		"google.com.":                   false,
		"GOOGLE.COM.":                   false,
	}

	for input, expected := range testCases {

		t.Run(fmt.Sprintf("IsCacheable query for %s should be %t", input, expected), func(t *testing.T) {
			q := dns.Question{
				Name:   input,
				Qtype:  4,
				Qclass: 1,
			}

			dnsResponse, err := models.NewDnsResponseFromDnsAnswers(
				[]models.DNSAnswer{
					{
						Name: input,
						Type: dns.TypeA,
						TTL:  1,
						Data: "192.168.1.1",
					},
				},
			)
			if err != nil {
				t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
			}

			cacheable := appConfig.IsCacheable(q, dnsResponse)
			if cacheable != expected {
				t.Errorf("%s cacheable is %t, should be %t", input, cacheable, expected)
			}
		})
	}
}

func TestIsCacheableDnsResponse(t *testing.T) {
	appConfig := AppConfig{
		DoNotCache: []string{"127.0.0.1", "*.google.com", "192.168.1.1/24", "203.0.113.1/16"},
	}
	appConfig.prepare()

	testCases := map[string]bool{
		"127.0.0.1":     false,
		"127.0.0.2":     true,
		"192.168.1.100": false,
		"203.0.113.1":   false,
	}

	for input, expected := range testCases {

		t.Run(fmt.Sprintf("IsCacheable response of %s should be %t", input, expected), func(t *testing.T) {
			q := dns.Question{
				Name:   input,
				Qtype:  4,
				Qclass: 1,
			}

			dnsResponse, err := models.NewDnsResponseFromDnsAnswers(
				[]models.DNSAnswer{
					{
						Name: "example.com.",
						Type: dns.TypeA,
						TTL:  1,
						Data: input,
					},
				},
			)
			if err != nil {
				t.Fatalf("unexpected error getting hardcoded dns response: %v", err)
			}

			cacheable := appConfig.IsCacheable(q, dnsResponse)
			if cacheable != expected {
				t.Errorf("%s cacheable is %t, should be %t", input, cacheable, expected)
			}
		})
	}
}
