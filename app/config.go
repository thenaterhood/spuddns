package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"

	"strings"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/models"
	"github.com/thenaterhood/spuddns/resolver"
	"github.com/thenaterhood/spuddns/system"
)

type AppConfig struct {
	EnableACLs bool `json:"enable_acls"`
	// The keys in this map are preshared keys to identify
	// the client. This list is only used if EnableACLs is true.
	// To add a catch-all item, use "*" as an ACL key, which is
	// used if a more-specific item does not exist.
	ACLs map[string]AclItem `json:"acls"`
	// Same as dnsmasq's --add-cpe-id option. This
	// overrides ForwardCpeId.
	AddCpeId    string `json:"add_cpe_id"`
	BindAddress string `json:"bind_address"`
	// Disable DNS caching
	DisableCache   bool `json:"disable_cache"`
	DisableMetrics bool `json:"disable_metrics"`
	DnsServerPort  int  `json:"dns_server_port"`
	// Generally nonstandard (this is NOT DoH/DNS over HTTPS)
	// but can be used if you're proxying DNS over HTTPS through
	// a server like nginx which will terminate the SSL connection
	DnsOverHttpEnable  bool   `json:"dns_over_http_enable"`
	DnsOverHttpPort    int    `json:"dns_over_http_port"`
	DnsOverTlsEnable   bool   `json:"dns_over_tls_enable"`
	DnsOverTlsPort     int    `json:"dns_over_tls_port"`
	DnsOverTlsCertFile string `json:"dns_over_tls_cert_file"`
	DnsOverTlsKeyFile  string `json:"dns_over_tls_key_file"`
	// Forward a CPE ID provided by the client. A CPE ID can be
	// provided by the client in either the DNS request itself
	// as is standard, OR if using DNS over HTTP, in the endpoint
	// URL, e.g. http://example.com/[SharedSecret]
	ForwardCpeId bool `json:"forward_cpe_id"`
	// Domains and networks (IPs and CIDR) that should not be
	// cached, if caching is enabled
	DoNotCache []string `json:"do_not_cache"`
	LogLevel   int      `json:"log_level"`
	MdnsEnable bool     `json:"mdns_enable"`
	// Whether to forward mDNS to an upstream server. Defaults
	// to disabled.
	MdnsForward     bool `json:"mdns_forward"`
	ForceMinimumTtl int  `json:"force_minimum_ttl"`
	// Attempt to maintain frequently used queries in
	// the cache so clients always received a cached response
	PredictiveCache bool `json:"predictive_cache"`
	// How many cache hits are required to proactively re-cache
	// a query result. Below this, and the entries will be considered
	// inactive and allowed to expire from the cache
	PredictiveThreshold int `json:"predictive_threshold"`
	// Keep common queries in the cache even when the upstream
	// resolver fails to resolve them so an outage of upstream
	// DNS doesn't cause a full network failure. Enabling this
	// also enables PredictiveCache.
	ResilientCache bool `json:"resilient_cache"`
	// If not empty, spuddns will periodically flush its cache to
	// this path and will load it at start to persist the cache between
	// restarts.
	PersistentCacheFile string              `json:"persistent_cache_file"`
	UpstreamResolvers   []string            `json:"upstream_resolvers"`
	ConditionalForwards map[string][]string `json:"conditional_forwards"`
	RespectResolveConf  bool                `json:"respect_resolvconf"`
	ResolvConfPath      string              `json:"resolvconf_path"`

	skip_cache_nets  []net.IPNet        `json:"-"`
	skip_cache_regex *regexp.Regexp     `json:"-"`
	ResolvConf       *system.ResolvConf `json:"-"`
	EtcHosts         *system.EtcHosts   `json:"-"`
}

// Access control list item
type AclItem struct {
	UpstreamResolvers []string `json:"upstream_resolvers"`
	ForwardCpeId      bool     `json:"forward_cpe_id"`
	AddCpeId          string   `json:"use_cpe_id"`
	UseSharedCache    bool     `json:"use_shared_cache"`
}

var loadedConfig *AppConfig

func strToIpNet(data string) *net.IPNet {
	ip := net.ParseIP(data)
	if ip == nil {
		_, net, err := net.ParseCIDR(data)
		if net != nil && err == nil {
			return net
		}

	} else {
		if ip.To4() != nil {
			return &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(32, 32),
			}
		} else {
			return &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(128, 128),
			}
		}
	}

	return nil
}

func (cfg *AppConfig) prepare() error {

	var skip_cache_regexes = []string{}

	for _, item := range cfg.DoNotCache {

		net := strToIpNet(item)
		if net != nil {
			cfg.skip_cache_nets = append(cfg.skip_cache_nets, *net)
		} else {
			if item[0] == '*' {
				item = item[1:]

				if item[0] == '.' {
					item = item[1:]
				}
				skip_cache_regexes = append(skip_cache_regexes, fmt.Sprintf(".+\\.%s(\\.)?", regexp.QuoteMeta(item)))
			}
			skip_cache_regexes = append(skip_cache_regexes, fmt.Sprintf("(^%s(\\.?)$)", regexp.QuoteMeta(item)))
		}
	}

	if len(skip_cache_regexes) > 0 {
		skip_cache_regex, err := regexp.Compile(fmt.Sprintf("(?i)%s", strings.Join(skip_cache_regexes, "|")))
		if err != nil {
			fmt.Printf("failed to compile cache exclude regex: %s", err)
		}
		if skip_cache_regex != nil {
			cfg.skip_cache_regex = skip_cache_regex
		}
	}

	if !cfg.RespectResolveConf && len(cfg.UpstreamResolvers) < 1 && len(cfg.ConditionalForwards) < 1 {
		cfg.UpstreamResolvers = []string{"8.8.8.8"}
	}
	return nil
}

func (cfg AppConfig) IsCacheable(query dns.Question, data *models.DnsResponse) bool {
	if cfg.DisableCache || data == nil || !data.IsSuccess() || data.FromCache {
		return false
	}

	answers, err := data.Answers()
	if err != nil {
		return false
	}

	for _, item := range answers {
		// FQDN (in question)
		if cfg.skip_cache_regex != nil && cfg.skip_cache_regex.MatchString(query.Name) {
			return false
		}

		// Network (in response)
		if item.Type == dns.TypeA || item.Type == dns.TypeAAAA {
			answerNet := strToIpNet(item.Data)
			if answerNet == nil {
				return false
			}

			dns_ip := answerNet.IP

			if dns_ip != nil {
				for _, skip_net := range cfg.skip_cache_nets {
					if skip_net.Contains(dns_ip) {
						return false
					}
				}
			}
		}
	}

	return true
}

func (cfg AppConfig) GetFullyQualifiedNames(name string) []string {
	if cfg.ResolvConf == nil {
		return []string{name}
	}

	return cfg.ResolvConf.GetFullyQualifiedNames(name)
}

func (cfg AppConfig) GetResolverConfig(appState *AppState, qname string, clientId *string, clientIp *string) (*resolver.DnsResolverConfig, error) {
	appCache := appState.Cache

	accessControl, err := cfg.GetACItem(clientId, clientIp)
	if err != nil {
		return nil, err
	}

	if accessControl != nil && !accessControl.UseSharedCache {
		appCache = &cache.DummyCache{}
	}
	resolverConfig := resolver.DnsResolverConfig{
		Servers:          []string{},
		Metrics:          appState.Metrics,
		Logger:           appState.Log,
		ForceMimimumTtl:  cfg.ForceMinimumTtl,
		Cache:            appCache,
		DefaultForwarder: appState.DefaultForwarder,
		Mdns: &resolver.MdnsConfig{
			Enable: cfg.MdnsEnable,
		},
	}

	resolverConfig.Servers = cfg.GetUpstreamResolvers(qname, clientId, clientIp)

	return &resolverConfig, nil
}

func (cfg AppConfig) GetUpstreamResolvers(name string, clientId *string, clientIp *string) []string {
	upstreamResolvers := []string{}
	accessControl, err := cfg.GetACItem(clientId, clientIp)

	if err != nil {
		return []string{}
	}

	if accessControl != nil {
		if len(accessControl.UpstreamResolvers) > 0 {
			return accessControl.UpstreamResolvers
		}
	}

	if len(cfg.ConditionalForwards) > 0 {
		subs := strings.Split(name, ".")
		slices.Reverse(subs)
		host := ""

		for _, segment := range subs {
			if segment == "." || segment == "" {
				continue
			}
			resolvers, ok := cfg.ConditionalForwards[host]
			if ok {
				return resolvers
			}

			if host == "" {
				host = segment
			} else {
				host = segment + "." + host
			}
		}
	}

	if cfg.ResolvConf != nil {
		if len(cfg.ResolvConf.Nameservers) > 0 {
			return cfg.ResolvConf.Nameservers
		}

		upstreamResolvers = append(upstreamResolvers, cfg.ResolvConf.Nameservers...)
	}

	upstreamResolvers = append(cfg.UpstreamResolvers, upstreamResolvers...)

	return upstreamResolvers
}

// Get the access control item for the given key
func (cfg AppConfig) GetACItem(key *string, ip *string) (*AclItem, error) {
	if !cfg.EnableACLs {
		return nil, nil
	}

	if key != nil {
		acl, ok := cfg.ACLs[*key]
		if ok {
			return &acl, nil
		}
	}

	if ip != nil {
		acl, ok := cfg.ACLs["ip:"+*ip]
		if ok {
			return &acl, nil
		}
	}

	acl, ok := cfg.ACLs["*"]
	if ok {
		return &acl, nil
	}

	return nil, fmt.Errorf("unrecognized client")
}

func GetDefaultConfig() AppConfig {
	return AppConfig{
		EnableACLs:          false,
		ACLs:                map[string]AclItem{},
		AddCpeId:            "",
		BindAddress:         "",
		DnsServerPort:       53,
		DnsOverHttpEnable:   false,
		DnsOverHttpPort:     8080,
		DnsOverTlsEnable:    false,
		DnsOverTlsPort:      853,
		DoNotCache:          []string{"127.0.0.1/16"},
		DisableCache:        false,
		DisableMetrics:      true,
		ForceMinimumTtl:     -1,
		LogLevel:            int(slog.LevelInfo),
		MdnsEnable:          true,
		MdnsForward:         false,
		PredictiveCache:     true,
		PredictiveThreshold: 10,
		PersistentCacheFile: "",
		ResilientCache:      true,
		UpstreamResolvers:   []string{},
		ConditionalForwards: map[string][]string{},
		RespectResolveConf:  true,
		ResolvConfPath:      "/etc/resolv.conf",
		skip_cache_nets:     []net.IPNet{},
	}
}

func getEnvBool(name string, def bool) bool {
	data := os.Getenv(name)
	if data == "" {
		return def
	}
	return data == "1" || strings.ToLower(data) == "true" || strings.ToLower(data) == "yes"
}

func getEnvList(name string, def []string) []string {
	data := os.Getenv(name)
	if data == "" {
		return def
	}
	return strings.Fields(data)
}

func getEnvInt(name string, def int) int {
	data := os.Getenv(name)

	if data == "" {
		return def
	}
	ret, err := strconv.Atoi(data)
	if err != nil {
		return def
	}

	return ret
}

func getEnvMapList(name string, def map[string][]string) map[string][]string {
	data := os.Getenv(name)
	ret := map[string][]string{}

	if data == "" {
		return def
	}

	list := strings.Fields(data)
	for _, item := range list {
		split := strings.SplitN(item, ":", 2)
		if len(split) != 2 {
			continue
		}

		ret[split[0]] = []string{split[1]}
	}

	return ret
}

func getEnvironmentConfig() AppConfig {
	config := GetDefaultConfig()

	config.DnsServerPort = getEnvInt("DNS_SERVER_PORT", config.DnsServerPort)
	config.DnsOverHttpEnable = getEnvBool("DNS_OVER_HTTP_ENABLE", config.DnsOverHttpEnable)
	config.MdnsEnable = getEnvBool("MDNS_ENABLE", config.MdnsEnable)
	config.RespectResolveConf = false // assuming docker
	config.UpstreamResolvers = getEnvList("UPSTREAM_RESOLVERS", config.UpstreamResolvers)
	config.ConditionalForwards = getEnvMapList("CONDITIONAL_FORWARDS", config.ConditionalForwards)
	config.DisableMetrics = getEnvBool("DISABLE_METRICS", config.DisableMetrics)

	config.ResolvConf = &system.ResolvConf{
		Search:      getEnvList("SEARCH_DOMAINS", []string{}),
		Nameservers: config.UpstreamResolvers,
		Options:     map[string]string{},
	}

	return config
}

func GetConfig(path string) (*AppConfig, error) {

	if loadedConfig != nil {
		return loadedConfig, nil
	}

	config := GetDefaultConfig()

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		config = getEnvironmentConfig()
		loadedConfig = &config
		return &config, nil
	}

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	loadedConfig = &config
	err = loadedConfig.prepare()

	return &config, err
}
