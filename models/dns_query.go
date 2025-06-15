package models

import (
	"bytes"
	"cmp"
	"fmt"

	"github.com/miekg/dns"
)

type InvalidQuery struct {
	Msg string
}

func (m InvalidQuery) Error() string {
	return fmt.Sprintf("Query is invalid: %s", m.Msg)
}

type DnsQuery struct {
	msg      dns.Msg
	ClientId *string
	ClientIp *string
}

// Construct a DnsQuery from a dns.Msg
func NewDnsQueryFromMsg(msg *dns.Msg) (*DnsQuery, error) {
	query := DnsQuery{
		msg: *cmp.Or(msg, new(dns.Msg)),
	}

	if _, err := query.msg.Pack(); err != nil {
		// This is a lazy way to validate the query is well formed
		return nil, err
	}

	return &query, nil
}

func NewDnsQueryFromQuestions(q []dns.Question) (*DnsQuery, error) {
	msg := new(dns.Msg)
	msg.Question = q

	return NewDnsQueryFromMsg(msg)
}

// Construct a DnsQuery from a byte representation of dns.Msg
func NewDnsQueryFromBytes(msg []byte) (*DnsQuery, error) {
	dnsReq := new(dns.Msg)
	if err := dnsReq.Unpack(msg); err != nil {
		return nil, err
	}

	return NewDnsQueryFromMsg(dnsReq)
}

func (d *DnsQuery) Equal(other *DnsQuery) bool {
	if other == nil && d == nil {
		return true
	}

	if other == nil {
		return false
	}

	if d.ClientId != other.ClientId {
		return false
	}

	if d.ClientIp != other.ClientIp {
		return false
	}

	packed, _ := d.msg.Pack()
	otherPacked, _ := other.msg.Pack()

	return bytes.Equal(packed, otherPacked)
}

func (d DnsQuery) WithDifferentQuestion(q dns.Question) (*DnsQuery, error) {
	msg := d.msg.Copy()
	msg.Question = []dns.Question{q}

	return NewDnsQueryFromMsg(msg)
}

// Return the first question on the query
func (d DnsQuery) FirstQuestion() *dns.Question {
	if len(d.msg.Question) < 1 {
		return nil
	}

	return &d.msg.Question[0]
}

// Return a copy (not reference) of the first question in the query
func (d DnsQuery) FirstQuestionCopy() *dns.Question {
	if len(d.msg.Question) < 1 {
		return nil
	}

	return &dns.Question{
		Name:   d.msg.Question[0].Name,
		Qtype:  d.msg.Question[0].Qtype,
		Qclass: d.msg.Question[0].Qclass,
	}
}

// Decompose a multiple-question query into a slice of
// single question queries
func (d DnsQuery) Decompose() []DnsQuery {
	queries := []DnsQuery{}

	for _, q := range d.msg.Question {
		tmp, err := d.msg.Pack()
		if err != nil {
			continue
		}

		msg := new(dns.Msg)
		if msg.Unpack(tmp) != nil {
			continue
		}

		msg.Question = []dns.Question{q}

		query, err := NewDnsQueryFromMsg(&d.msg)
		if err != nil {
			continue
		}
		queries = append(queries, *query)
	}

	return queries
}

// Gets the CPE ID, if any, from a DNS message
func (d DnsQuery) CpeId() string {
	if d.msg.IsEdns0() != nil {
		for _, opt := range d.msg.IsEdns0().Option {
			switch e := opt.(type) {
			case *dns.EDNS0_LOCAL:
				if e.Code == EDNS0CpeIdOptionCode {
					return string(e.Data)
				}
			}
		}
	}

	return ""
}

// Adds a CPE ID (and OPT record, if needed) to a DNS
// message.
func (d *DnsQuery) SetCpeId(cpeId string) *DnsQuery {
	if cpeId != "" {
		opt := d.msg.IsEdns0()

		if opt != nil {
			for _, edns0 := range d.msg.IsEdns0().Option {
				switch e := edns0.(type) {
				case *dns.EDNS0_LOCAL:
					if e.Code == EDNS0CpeIdOptionCode {
						e.Data = []byte(cpeId)
						return d
					}
				}
			}
		} else {
			opt = new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			d.msg.Extra = append(d.msg.Extra, opt)
		}

		opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
			Code: EDNS0CpeIdOptionCode,
			Data: []byte(cpeId),
		})
	}

	return d
}

func (d DnsQuery) ResolveWithAsync(client DnsQueryClient, response chan *DnsResponse) {
	go func() {
		answer, err := d.ResolveWith(client)

		if answer != nil && err == nil {
			response <- answer
			return
		}

		response <- nil
	}()
}

func (d DnsQuery) ResolveWith(client DnsQueryClient) (*DnsResponse, error) {
	answers := []DNSAnswer{}
	fromCache := false

	switch d.msg.Opcode {
	case dns.OpcodeQuery:
		for _, questionQuery := range d.Decompose() {
			answer, err := client.QueryDns(questionQuery)

			if err != nil {
				return NewServFailDnsResponse(), err
			}

			if !answer.IsSuccess() {
				return nil, nil
			}

			if answer == nil {
				return NewNoErrorDnsResponse(), nil
			}

			decomposedAnswers, err := answer.Answers()
			if err != nil {
				return NewServFailDnsResponse(), err
			}

			answers = append(answers, decomposedAnswers...)

			fromCache = cmp.Or(fromCache, answer.FromCache)
		}
	default:
		return NewServFailDnsResponse(), InvalidQuery{fmt.Sprintf("unsupported opcode '%d'", d.msg.Opcode)}
	}

	response, err := NewDnsResponseFromDnsAnswers(answers)
	if err != nil {
		return nil, err
	}

	response.FromCache = fromCache

	return response, nil
}

func (d DnsQuery) NameExists(client DnsQueryClient) bool {
	aChannel := make(chan *DnsResponse)
	aaaaChannel := make(chan *DnsResponse)

	aQuery, err := d.WithDifferentQuestion(dns.Question{
		Name:   d.FirstQuestion().Name,
		Qtype:  dns.TypeA,
		Qclass: d.FirstQuestion().Qclass,
	})

	if err == nil && aQuery != nil {
		aQuery.ResolveWithAsync(client, aChannel)
	} else {
		close(aChannel)
	}

	aaaaQuery, err := d.WithDifferentQuestion(dns.Question{
		Name:   d.FirstQuestion().Name,
		Qtype:  dns.TypeAAAA,
		Qclass: d.FirstQuestion().Qclass,
	})

	if err == nil && aaaaQuery != nil {
		aaaaQuery.ResolveWithAsync(client, aaaaChannel)
	} else {
		close(aaaaChannel)
	}

	aResult := <-aChannel
	aaaResult := <-aaaaChannel

	if aResult != nil && aResult.IsSuccess() {
		return true
	}

	if aaaResult != nil && aaaResult.IsSuccess() {
		return true
	}

	return false
}

// Clear extra RRs from the query message
func (q *DnsQuery) ClearExtra() *DnsQuery {
	q.msg.Extra = []dns.RR{}
	return q
}

// Pack this query back into a dns.Msg
func (q DnsQuery) PreparedMsg() *dns.Msg {
	m := new(dns.Msg)

	// Assuming these are well-formed at this point
	packed, _ := q.msg.Pack()
	m.Unpack(packed)

	m.RecursionDesired = true

	return m
}
