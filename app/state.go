package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/thenaterhood/spuddns/cache"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
	"github.com/thenaterhood/spuddns/resolver"
)

type AppState struct {
	Cache            cache.Cache
	DefaultForwarder models.DnsQueryClient
	DnsPipeline      *chan models.DnsExchange
	Log              *slog.Logger
	Metrics          metrics.MetricsInterface
}

func (appState *AppState) ResolveQueryOnly(query models.DnsQuery, appConfig *AppConfig) (*models.DnsExchange, error) {
	question := query.FirstQuestionCopy()
	hasUpstreams := false
	var answer *models.DnsResponse
	var err error

	forwardCpeId := appConfig.ForwardCpeId
	cpeId := appConfig.AddCpeId

	if !forwardCpeId {
		query.ClearExtra()
	}

	if query.CpeId() == "" {
		query.SetCpeId(cpeId)
	}

	if question == nil {
		return &models.DnsExchange{
			Response: *models.NewServFailDnsResponse(),
			Question: *query.FirstQuestion(),
		}, fmt.Errorf("refusing to process empty question")
	}

	if appConfig.EtcHosts != nil {
		answer, err = query.ResolveWith(appConfig.EtcHosts, context.Background())
		if answer != nil && err == nil {
			return &models.DnsExchange{Response: *answer, Question: *query.FirstQuestion()}, nil
		}
	}

	names := appConfig.GetFullyQualifiedNames(question.Name)

	for _, alternateName := range names {
		resolverConfig, err := appConfig.GetResolverConfig(appState, alternateName, query.ClientId, query.ClientIp)
		if err != nil {
			return &models.DnsExchange{Response: *models.NewRefusedDnsResponse(), Question: *query.FirstQuestion()}, err
		}

		question.Name = alternateName
		modifiedQuery, modifiedQueryErr := query.WithDifferentQuestion(*question)
		if modifiedQueryErr != nil {
			continue
		}

		if len(resolverConfig.Servers) > 0 {
			hasUpstreams = true
		}

		forwarder := resolver.GetDnsResolver(*resolverConfig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		answer, err = modifiedQuery.ResolveWith(forwarder, ctx)

		if answer != nil && answer.IsSuccess() {
			return &models.DnsExchange{Response: *answer, Question: *modifiedQuery.FirstQuestion()}, nil
		}

		if err != nil {
			return &models.DnsExchange{Response: *models.NewServFailDnsResponse(), Question: *modifiedQuery.FirstQuestion()}, err
		}

		exists := modifiedQuery.NameExists(forwarder)
		if exists {
			answer := models.NewNoErrorDnsResponse()
			answer.ChangeNameFrom(query.FirstQuestion().Name, alternateName, 5*time.Minute)
			if len(resolverConfig.Servers) > 0 {
				answer.Resolver = resolverConfig.Servers[0]
			}
			return &models.DnsExchange{Response: *models.NewServFailDnsResponse(), Question: *modifiedQuery.FirstQuestion()}, nil
		}
	}

	answer = models.NewNXDomainDnsResponse()
	answer.RecursionAvailable = hasUpstreams

	return &models.DnsExchange{Response: *answer, Question: *query.FirstQuestion()}, err
}

func (appState *AppState) ResolveQueryComplete(query models.DnsQuery, appConfig *AppConfig) (*models.DnsResponse, error) {

	dnsExchange, err := appState.ResolveQueryOnly(query, appConfig)
	if err != nil {
		appState.Log.Error("error resolving query", "err", err)
	}

	if dnsExchange != nil && dnsExchange.Response.IsSuccess() {
		if dnsExchange.Response.FromCache {
			appState.Metrics.IncQueriesAnsweredFromCache()
		} else {
			if appState.DnsPipeline != nil {
				go func() {
					*appState.DnsPipeline <- *dnsExchange
				}()

			}
		}
		appState.Metrics.IncQueriesAnswered()
		return &dnsExchange.Response, nil
	}

	return &dnsExchange.Response, err
}
