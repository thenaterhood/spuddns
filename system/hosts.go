package system

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/models"
)

type EtcHosts struct {
	Path string
	log  *slog.Logger
}

type (
	EtcHostsARecords    map[string]string
	EtcHostsAAAARecords map[string]string
)

func NewEtcHosts(log *slog.Logger) *EtcHosts {
	etcHosts := EtcHosts{
		Path: "/etc/hosts",
		log:  log,
	}

	return &etcHosts
}

func (hosts *EtcHosts) QueryDns(query models.DnsQuery) (*models.DnsResponse, error) {
	qname := query.FirstQuestion().Name
	qtype := query.FirstQuestion().Qtype

	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil, nil
	}

	hosts.log.Debug("attempting to resolve from etc/hosts", "qname", qname)

	aRecords, aaaaRecords, err := hosts.ReadFromFile()
	if err != nil {
		return nil, err
	}

	if qtype == dns.TypeA {
		addr, ok := aRecords[qname]
		if !ok {
			return models.NewNXDomainDnsResponse(), nil
		}

		return models.NewDnsResponseFromDnsAnswers(
			[]models.DNSAnswer{
				{
					Name: qname,
					Type: qtype,
					TTL:  30 * time.Second,
					Data: addr,
				},
			},
		)
	} else {
		addr, ok := aaaaRecords[qname]
		if !ok {
			return models.NewNXDomainDnsResponse(), nil
		}

		return models.NewDnsResponseFromDnsAnswers(
			[]models.DNSAnswer{
				{
					Name: qname,
					Type: qtype,
					TTL:  30 * time.Second,
					Data: addr,
				},
			},
		)
	}
}

func (hosts *EtcHosts) ReadFromFile() (EtcHostsARecords, EtcHostsAAAARecords, error) {
	conf, err := os.Open(hosts.Path)
	if err != nil {
		return nil, nil, err
	}

	defer conf.Close()

	return hosts.ReadFromReader(conf, hosts.log)
}

func (hosts *EtcHosts) ReadFromReader(reader io.Reader, log *slog.Logger) (EtcHostsARecords, EtcHostsAAAARecords, error) {
	scanner := bufio.NewScanner(reader)
	var aRecords EtcHostsARecords = map[string]string{}
	var aaaaRecords EtcHostsAAAARecords = map[string]string{}

	for scanner.Scan() {
		words := strings.Fields(scanner.Text())

		if len(words) < 2 {
			continue
		}

		if words[0] == "#" {
			continue
		}

		addr := net.ParseIP(words[0])
		if addr == nil {
			continue
		}

		for _, host := range words[1:] {
			if addr.To4() != nil {
				aRecords[makeQualified(host)] = addr.String()
			} else {
				aaaaRecords[makeQualified(host)] = addr.String()
			}
		}
	}

	return aRecords, aaaaRecords, nil
}
