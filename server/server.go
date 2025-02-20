package server

import (
	"cmp"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/app"
	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/models"
	"github.com/thenaterhood/spuddns/resolver"
)

type DnsServer struct {
	appConfig            *app.AppConfig
	appState             *app.AppState
	standard_dns_server  *dns.Server
	dns_over_tls_server  *dns.Server
	dns_over_http_server *http.Server
}

func (ds *DnsServer) getDnsResponse(query models.DnsQuery) (*models.DnsResponse, error) {
	accessControl, err := ds.appConfig.GetACItem(query.ClientId, query.ClientIp)
	if err != nil {
		return models.NewRefusedDnsResponse(), models.UnauthorizedError{}
	}

	forwardCpeId := ds.appConfig.ForwardCpeId
	cpeId := ds.appConfig.AddCpeId

	if accessControl != nil {
		forwardCpeId = accessControl.ForwardCpeId
		cpeId = accessControl.AddCpeId
	}

	if !forwardCpeId {
		query.ClearExtra()
	}

	if query.CpeId() == "" {
		query.SetCpeId(cpeId)
	}

	var answer *models.DnsResponse
	question := query.FirstQuestionCopy()
	if question == nil {
		ds.appState.Log.Warn("refusing to process empty dns question")
		return models.NewServFailDnsResponse(), nil
	}

	appCache := ds.appState.Cache
	resolverConfig := resolver.DnsResolverConfig{
		Servers:         []string{},
		Metrics:         ds.appState.Metrics,
		Logger:          ds.appState.Log,
		ForceMimimumTtl: ds.appConfig.ForceMinimumTtl,
	}

	for _, alternateName := range ds.appConfig.GetFullyQualifiedNames(question.Name) {
		ds.appState.Log.Debug("trying name", "name", alternateName, "originalName", question.Name)
		question.Name = alternateName
		modifiedQuery, modifiedQueryErr := query.WithDifferentQuestion(*question)
		if modifiedQueryErr != nil {
			ds.appState.Log.Warn("alternate name query was invalid", "alternateName", alternateName, "error", err)
			continue
		}

		resolverConfig.Servers = ds.appConfig.GetUpstreamResolvers(alternateName)

		if accessControl != nil {
			if len(accessControl.UpstreamResolvers) > 0 {
				resolverConfig.Servers = accessControl.UpstreamResolvers
			}

			if !accessControl.UseSharedCache {
				appCache = &cache.DummyCache{}
			}
		}

		forwarder := cmp.Or(ds.appState.DefaultForwarder, resolver.GetDnsResolver(resolverConfig, appCache))
		answer, err = modifiedQuery.ResolveWith(forwarder)

		if answer != nil {
			if ds.appState.DnsPipeline != nil {
				go func() {
					*ds.appState.DnsPipeline <- models.DnsExchange{Question: *question, Response: *answer}
				}()
			}

			if answer.FromCache {
				ds.appState.Metrics.IncQueriesAnsweredFromCache()
			}
			ds.appState.Metrics.IncQueriesAnswered()
			return answer, nil
		}
	}

	if err != nil {
		ds.appState.Log.Warn("error resolving dns request", "error", err)
		answer = models.NewServFailDnsResponse()
	} else if answer == nil {
		answer = models.NewNXDomainDnsResponse()
	} else if answers, _ := answer.Answers(); len(answers) < 1 {
		answer = models.NewNXDomainDnsResponse()
	}

	return answer, err
}

// Handle a DNS over HTTP(S) request
func (ds DnsServer) handleDnsOverHTTP(w http.ResponseWriter, r *http.Request) {
	responseTimer := ds.appState.Metrics.GetResponseTimer()
	defer ds.appState.Metrics.ObserveTimer(responseTimer)
	var msg []byte
	var err error

	acceptType := strings.ToLower(r.Header.Get("accept"))
	acceptableTypes := map[string]func(*dns.Msg){
		models.ContentTypeJson: func(msg *dns.Msg) {
			w.Header().Set("Content-Type", models.ContentTypeJson)

			switch err {
			case models.UnauthorizedError{}:
				ds.appState.Log.Warn("unauthorized request", "path", r.URL.Path)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			json, err := json.Marshal(msg.Answer)
			if err != nil {
				ds.appState.Log.Warn("failed to json marshal dns response", "err", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
			} else {
				w.Write(json)
			}
		},
		models.ContentTypeDnsMessage: func(msg *dns.Msg) {
			packed, _ := msg.Pack()
			w.Header().Set("Content-Type", models.ContentTypeDnsMessage)
			w.Write(packed)
		},
	}

	writeResp, ok := acceptableTypes[acceptType]
	if !ok {
		ds.appState.Log.Debug("unsupported content type requested", "content_type", acceptType)
		http.Error(w, "Not acceptable", http.StatusNotAcceptable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		msg, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	case http.MethodPost:
		msg, err = io.ReadAll(r.Body)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	dnsReq, err := models.NewDnsQueryFromBytes(msg)
	if err != nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	ds.appState.Log.Debug("got dns over http request", "msg", dnsReq)

	cpeId := r.URL.Query().Get("cpe_id")
	auth := cmp.Or(r.PathValue("auth"), dnsReq.CpeId(), cpeId, "")
	if cpeId != "" {
		dnsReq.SetCpeId(cpeId)
	}
	dnsReq.ClientId = &auth
	dnsReq.ClientIp = &r.RemoteAddr

	resp, err := ds.getDnsResponse(*dnsReq)
	if err != nil {
		ds.appState.Log.Warn("error handling dns over http request", "error", err)
	}
	if resp != nil {
		writeResp(resp.AsReplyToMsg(dnsReq.PreparedMsg()))
	} else {
		writeResp(models.NewServFailDnsResponse().AsReplyToMsg(dnsReq.PreparedMsg()))
	}
}

// Handle a standard DNS request
func (ds *DnsServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	responseTimer := ds.appState.Metrics.GetResponseTimer()
	defer ds.appState.Metrics.ObserveTimer(responseTimer)
	ds.appState.Log.Debug("got dns request", "msg", r)

	dnsQuery, err := models.NewDnsQueryFromMsg(r)
	if err != nil {
		ds.appState.Log.Warn("failed to get DnsQuery from msg", "err", err)
		w.WriteMsg(models.NewServFailDnsResponse().AsReplyToMsg(r))
		return
	}

	auth := dnsQuery.CpeId()
	clientIp := strings.Split(w.RemoteAddr().String(), ":")[0]

	dnsQuery.ClientId = &auth
	dnsQuery.ClientIp = &clientIp

	resp, err := ds.getDnsResponse(*dnsQuery)
	if err != nil {
		ds.appState.Log.Warn("error handling dns request", "error", err)
	}

	if resp != nil {
		err = w.WriteMsg(resp.AsReplyToMsg(r))
		if err != nil {
			ds.appState.Log.Warn("failed to write dns response", "err", err, "msg", resp.AsReplyToMsg(r))
		}
		return
	}

	w.WriteMsg(models.NewServFailDnsResponse().AsReplyToMsg(r))
}

func (ds *DnsServer) Start() error {
	if ds.dns_over_tls_server != nil {
		defer ds.dns_over_tls_server.Shutdown()
		go func() {
			ds.appState.Log.Info("starting DNS over HTTPS server", "addr", ds.dns_over_tls_server.Addr)
			err := ds.dns_over_tls_server.ListenAndServe()
			if err != nil {
				ds.appState.Log.Error("failed to start dns over https server", "error", err.Error())
			}
		}()
	}

	if ds.dns_over_http_server != nil {
		go func() {
			ds.appState.Log.Info("start DNS over HTTP server", "addr", ds.dns_over_http_server.Addr)
			err := ds.dns_over_http_server.ListenAndServe()
			if err != nil {
				ds.appState.Log.Error("failed to start dns over http server", "error", err.Error())
			}
		}()
	}

	ds.appState.Log.Info("starting DNS server", "port", ds.appConfig.DnsServerPort)
	err := ds.standard_dns_server.ListenAndServe()
	defer ds.standard_dns_server.Shutdown()
	if err != nil {
		ds.appState.Log.Error("failed to start server", "error", err.Error())
	}

	return nil
}

func NewDnsServer(config app.AppConfig, state app.AppState) DnsServer {
	port := config.DnsServerPort
	bind := config.BindAddress

	server := DnsServer{
		appConfig: &config,
		appState:  &state,
		standard_dns_server: &dns.Server{
			Addr: fmt.Sprintf("%s:%d", bind, port),
			Net:  "udp",
		},
	}

	server.standard_dns_server.Handler = dns.HandlerFunc(server.handleDNSRequest)

	if config.DnsOverTlsEnable {
		cert, err := tls.LoadX509KeyPair(config.DnsOverTlsCertFile, config.DnsOverTlsKeyFile)
		if err != nil {
			log.Fatalf("Error loading certificate: %v", err)
		}

		// Create TLS configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		server.dns_over_tls_server = &dns.Server{
			Addr:      fmt.Sprintf("%s:%d", bind, config.DnsOverTlsPort),
			Net:       "tcp-tls",
			TLSConfig: tlsConfig,
			Handler:   dns.HandlerFunc(server.handleDNSRequest),
		}
	}

	if config.DnsOverHttpEnable {
		mux := http.NewServeMux()
		mux.HandleFunc("/", server.handleDnsOverHTTP)
		mux.HandleFunc("/dns-query", server.handleDnsOverHTTP)
		mux.HandleFunc("/{auth}", server.handleDnsOverHTTP)
		mux.HandleFunc("/{auth}/dns-query", server.handleDnsOverHTTP)
		server.dns_over_http_server = &http.Server{
			Addr:    fmt.Sprintf("%s:%d", bind, config.DnsOverHttpPort),
			Handler: mux,
		}
	}

	return server
}
