package server

import (
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/app"
	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
	"github.com/thenaterhood/spuddns/resolver"
)

func getAppState(cache cache.Cache) *app.AppState {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.Level(slog.LevelDebug),
	}))
	return &app.AppState{
		Cache:   cache,
		Metrics: &metrics.DummyMetrics{},
		Log:     log,
		DefaultForwarder: resolver.GetDnsResolver(resolver.DnsResolverConfig{
			Logger: log,
			Static: map[string]string{
				"example.com": "127.0.0.1",
				"google.com":  "127.0.0.2",
			},
		}, cache),
	}
}

func runDnsServerTest(t *testing.T, appCfg app.AppConfig, appState app.AppState, clientId *string) *dns.Msg {
	server := NewDnsServer(appCfg, appState)

	waitLock := sync.Mutex{}
	server.standard_dns_server.NotifyStartedFunc = waitLock.Unlock
	server.standard_dns_server.Addr = ":0"
	waitLock.Lock()
	defer server.standard_dns_server.Shutdown()

	go func() {
		server.Start()
	}()
	waitLock.Lock()

	q, err := models.NewDnsQueryFromQuestions(
		[]dns.Question{{Name: "example.com.", Qtype: dns.TypeA}},
	)
	if err != nil {
		t.Fatalf("invalid dns question: %v", err)
	}
	if clientId != nil {
		q.SetCpeId(*clientId)
	}

	c := new(dns.Client)
	m := q.PreparedMsg()

	addr := server.standard_dns_server.PacketConn.LocalAddr().String() // Get address via the PacketConn that gets set.
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal("failed to exchange example.com", err)
	}

	return r
}

func TestServerResolvesBasicQuery(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0

	r := runDnsServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), nil)
	a := r.Answer[0].(*dns.A).A
	if a.String() != "127.0.0.1" {
		t.Error("unexpected result for example.com", a.String(), "!= 127.0.0.1")
	}
}

func TestServerResolvesEdnsQueryAuthNotRequired(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0

	r := runDnsServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), nil)

	a := r.Answer[0].(*dns.A).A
	if a.String() != "127.0.0.1" {
		t.Error("unexpected result for example.com", a.String(), "!= 127.0.0.1")
	}
}

func TestServerResolvesEdnsQueryBadAuth(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.EnableACLs = true
	appCfg.ACLs = map[string]app.AclItem{
		"example": {},
	}

	cpeId := "test"
	r := runDnsServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), &cpeId)

	if r.Rcode != dns.RcodeRefused {
		t.Errorf("expected opcode REFUSED (%d), got %d", dns.RcodeRefused, r.Rcode)
	}
	if len(r.Answer) > 0 {
		t.Error("got answers but did not expect answers")
	}
}

func TestServerResolvesEdnsQueryGoodAuth(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.EnableACLs = true
	appCfg.ACLs = map[string]app.AclItem{
		"test": {},
	}

	cpeId := "test"
	r := runDnsServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), &cpeId)

	a := r.Answer[0].(*dns.A).A
	if a.String() != "127.0.0.1" {
		t.Error("unexpected result for example.com", a.String(), "!= 127.0.0.1")
	}
}

func TestServerRejectsNonEdnsQueryWhenAuthRequired(t *testing.T) {

	appCfg := app.GetDefaultConfig()
	appCfg.BindAddress = ""
	appCfg.DnsServerPort = 0
	appCfg.EnableACLs = true
	appCfg.ACLs = map[string]app.AclItem{
		"example": {},
	}

	r := runDnsServerTest(t, appCfg, *getAppState(&cache.DummyCache{}), nil)

	if r.Rcode != dns.RcodeRefused {
		t.Errorf("expected opcode REFUSED (%d), got %d", dns.RcodeRefused, r.Rcode)
	}
	if len(r.Answer) > 0 {
		t.Error("got answers but did not expect answers")
	}
}
