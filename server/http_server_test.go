package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/app"
	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/models"
)

func runHttpServerTest(
	t *testing.T,
	appCfg app.AppConfig,
	appState app.AppState,
	method string,
	ednsClientId *string,
	httpClientId *string,
) *dns.Msg {
	dnsServer := NewDnsServer(appCfg, appState)

	responseRecorder := httptest.NewRecorder()
	cpeId := ""
	if ednsClientId != nil {
		cpeId = *ednsClientId
	}

	q, err := models.NewDnsQueryFromQuestions([]dns.Question{
		{
			Name:  "example.com.",
			Qtype: dns.TypeA,
		},
	})
	if err != nil {
		t.Fatalf("invalid dns question: %v", err)
	}
	q.SetCpeId(cpeId)

	m := q.PreparedMsg()

	url := "/"
	if httpClientId != nil {
		url = fmt.Sprintf("%s%s", url, *httpClientId)
	}

	packedQuery, err := m.Pack()
	if err != nil {
		t.Errorf("unexpected error while packing dns query: %v", err)
	}

	if method == http.MethodGet {
		url = fmt.Sprintf("%s?dns=%s", url, string(packedQuery))
	}

	if dnsServer.dns_over_http_server == nil {
		t.Fatalf("dns over http is not enabled")
	}

	request := httptest.NewRequest(method, url, bytes.NewBuffer(packedQuery))
	request.Header.Set("Accept", models.ContentTypeDnsMessage)
	dnsServer.dns_over_http_server.Handler.ServeHTTP(responseRecorder, request)

	msg, err := io.ReadAll(responseRecorder.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(msg); err != nil {
		t.Fatalf("invalid http dns message: %v", err)
	}

	return dnsResp
}

func TestHTTPServerResolvesBasicQuery(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.DnsOverHttpEnable = true

	r := runHttpServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), http.MethodPost, nil, nil)
	if len(r.Answer) < 1 {
		t.Fatal("got no answers but expected answers")
	}
	a := r.Answer[0].(*dns.A).A
	if a.String() != "127.0.0.1" {
		t.Error("unexpected result for example.com", a.String(), "!= 127.0.0.1")
	}
}

func TestHTTPServerResolvesEdnsQueryAuthNotRequired(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.DnsOverHttpEnable = true

	cpeId := "test"
	r := runHttpServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), http.MethodPost, &cpeId, nil)
	if len(r.Answer) < 1 {
		t.Fatal("got no answers but expected answers")
	}
	a := r.Answer[0].(*dns.A).A
	if a.String() != "127.0.0.1" {
		t.Error("unexpected result for example.com", a, "!= 127.0.0.1")
	}
}

func TestHTTPServerResolvesAuthedQueryAuthNotRequired(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.DnsOverHttpEnable = true

	cpeId := "test"
	r := runHttpServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), http.MethodPost, nil, &cpeId)
	if len(r.Answer) < 1 {
		t.Fatal("got no answers but expected answers")
	}
	a := r.Answer[0].(*dns.A).A
	if a.String() != "127.0.0.1" {
		t.Error("unexpected result for example.com", a, "!= 127.0.0.1")
	}
}

func TestHTTPServerResolvesQueryBadEdnsAuth(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.DnsOverHttpEnable = true
	appCfg.EnableACLs = true
	appCfg.ACLs = map[string]app.AclItem{
		"example": {},
	}

	cpeId := "test"
	r := runHttpServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), http.MethodPost, &cpeId, nil)

	if r.Rcode != dns.RcodeRefused {
		t.Errorf("expected opcode REFUSED (%d), got %d", dns.RcodeRefused, r.Rcode)
	}
	if len(r.Answer) > 0 {
		t.Error("got answers but did not expect answers")
	}
}

func TestHTTPServerResolvesQueryBadAuth(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.DnsOverHttpEnable = true
	appCfg.EnableACLs = true
	appCfg.ACLs = map[string]app.AclItem{
		"example": {},
	}

	cpeId := "test"
	r := runHttpServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), http.MethodPost, nil, &cpeId)

	if r.Rcode != dns.RcodeRefused {
		t.Errorf("expected opcode REFUSED (%d), got %d", dns.RcodeRefused, r.Rcode)
	}
	if len(r.Answer) > 0 {
		t.Error("got answers but did not expect answers")
	}
}

func TestHTTPServerResolvesQueryGoodEdnsAuth(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.DnsOverHttpEnable = true
	appCfg.EnableACLs = true
	appCfg.ACLs = map[string]app.AclItem{
		"test": {},
	}

	cpeId := "test"
	r := runHttpServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), http.MethodPost, &cpeId, nil)
	if len(r.Answer) < 1 {
		t.Fatal("got no answers but expected answers")
	}
	a := r.Answer[0].(*dns.A).A
	if a.String() != "127.0.0.1" {
		t.Error("unexpected result for example.com", a, "!= 127.0.0.1")
	}
}

func TestHTTPServerResolvesQueryGoodAuth(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.DnsOverHttpEnable = true
	appCfg.EnableACLs = true
	appCfg.ACLs = map[string]app.AclItem{
		"test": {},
	}

	cpeId := "test"
	r := runHttpServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), http.MethodPost, nil, &cpeId)

	fmt.Printf("%d\n", r.Rcode)
	if len(r.Answer) < 1 {
		t.Fatal("got no answers but expected answers")
	}
	a := r.Answer[0].(*dns.A).A
	if a.String() != "127.0.0.1" {
		t.Error("unexpected result for example.com", a, "!= 127.0.0.1")
	}
}

func TestHTTPServerRejectsMissingAuth(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.DnsOverHttpEnable = true
	appCfg.EnableACLs = true
	appCfg.ACLs = map[string]app.AclItem{
		"example": {},
	}

	r := runHttpServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), http.MethodPost, nil, nil)

	if r.Rcode != dns.RcodeRefused {
		t.Errorf("expected opcode REFUSED (%d), got %d", dns.RcodeRefused, r.Rcode)
	}
	if len(r.Answer) > 0 {
		t.Error("got answers but did not expect answers")
	}
}
