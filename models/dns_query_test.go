package models

import (
	"bytes"
	"cmp"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type FakeResolver struct {
	records map[string]string
}

func (f *FakeResolver) QueryDns(query DnsQuery) (*DnsResponse, error) {
	answer, ok := f.records[fmt.Sprintf("%s:%d", query.FirstQuestion().Name, query.FirstQuestion().Qtype)]

	if !ok {
		return NewNXDomainDnsResponse(), nil
	}

	return NewDnsResponseFromDnsAnswers(
		[]DNSAnswer{
			{
				Name: query.FirstQuestion().Name,
				Type: query.FirstQuestion().Qtype,
				TTL:  30 * time.Second,
				Data: answer,
			},
		},
	)
}

func TestGetCpeId(t *testing.T) {

	type test struct {
		expectedCpeId string
		inputMsg      *dns.Msg
	}

	tests := []test{
		{
			expectedCpeId: "",
			inputMsg:      nil,
		},
		{
			expectedCpeId: "",
			inputMsg:      new(dns.Msg),
		},
		{
			expectedCpeId: "test",
			inputMsg:      new(DnsQuery).SetCpeId("test").PreparedMsg(),
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("GetCpeId(%v) -> '%s'", test.inputMsg, test.expectedCpeId), func(t *testing.T) {
			dnsQuery, err := NewDnsQueryFromMsg(test.inputMsg)
			if err != nil {
				t.Fatalf("failed to get dns query from msg: %v", err)
			}
			output := dnsQuery.CpeId()

			if output != test.expectedCpeId {
				t.Errorf("GetCpeId(%v) returned '%s', expected '%s'", test.inputMsg, output, test.expectedCpeId)
			}
		})
	}
}

func TestSetCpeId(t *testing.T) {

	type test struct {
		expectedCpeId string
		inputMsg      *dns.Msg
	}

	tests := []test{
		{
			expectedCpeId: "",
			inputMsg:      nil,
		},
		{
			expectedCpeId: "",
			inputMsg:      new(dns.Msg),
		},
		{
			expectedCpeId: "test",
			inputMsg:      new(DnsQuery).SetCpeId("test").PreparedMsg(),
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("SetCpeId(%v, '%s')", test.inputMsg, test.expectedCpeId), func(t *testing.T) {
			query, err := NewDnsQueryFromMsg(cmp.Or(test.inputMsg, new(dns.Msg)))
			if err != nil {
				t.Fatalf("unexpected error creating dns query: %v", err)
			}
			query.SetCpeId(test.expectedCpeId)

			if query.CpeId() != test.expectedCpeId {
				t.Errorf("SetCpeId(%v, %s) produced DnsQuery with cpeId '%s'", test.inputMsg, test.expectedCpeId, query.CpeId())
			}

			query, err = NewDnsQueryFromMsg(query.PreparedMsg())
			if err != nil {
				t.Errorf("unexpected error creating dns query from updated msg: %v", err)
			}

			if query.CpeId() != test.expectedCpeId {
				t.Errorf("SetCpeId(%v, %s) produced dns.Msg with cpeId '%s'", test.inputMsg, test.expectedCpeId, query.CpeId())
			}
		})
	}
}

func TestNewQuery(t *testing.T) {

	type test struct {
		inputMsg      *dns.Msg
		expectedError error
		expectedQuery *DnsQuery
		name          string
	}

	invalidMsg := new(dns.Msg)
	invalidMsg.Rcode = 255 // invalid if extended fields are not set

	validMsg := new(dns.Msg)
	validMsg.Rcode = dns.RcodeSuccess
	validMsg.Question = append(validMsg.Question, dns.Question{Name: "example.com."})

	tests := []test{
		{
			inputMsg:      nil,
			expectedError: nil,
			expectedQuery: &DnsQuery{msg: *new(dns.Msg)},
			name:          "nil message does not break",
		},
		{
			inputMsg:      new(dns.Msg),
			expectedError: nil,
			expectedQuery: &DnsQuery{msg: *new(dns.Msg)},
			name:          "empty message does not break",
		},
		{
			inputMsg:      invalidMsg,
			expectedError: dns.ErrExtendedRcode,
			expectedQuery: nil,
			name:          "invalid message returns error",
		},
		{
			inputMsg:      validMsg,
			expectedError: nil,
			expectedQuery: &DnsQuery{msg: *validMsg},
			name:          "valid message returns expected query",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query, err := NewDnsQueryFromMsg(test.inputMsg)

			if err != test.expectedError {
				t.Errorf("got wrong error for input. actual = '%v', expected = '%v'", err, test.expectedError)
			}

			if !query.Equal(test.expectedQuery) {
				t.Errorf("got wrong query for input. actual = '%v', expected = '%v'", query, test.expectedQuery)
			}

			if test.expectedQuery != nil {
				if len(query.Decompose()) != len(test.expectedQuery.Decompose()) {
					t.Errorf(
						"query had wrong number of questions: expected = %d, actual = %d",
						len(test.expectedQuery.Decompose()),
						len(query.Decompose()),
					)
				}

				if test.expectedQuery.FirstQuestion() != nil && query.FirstQuestion() != nil {
					if *test.expectedQuery.FirstQuestion() != *query.FirstQuestion() {
						t.Error(
							"non-nil query questions did not match",
						)
					}
				} else {
					if test.expectedQuery.FirstQuestion() != query.FirstQuestion() {
						t.Error(
							"query questions did not match",
						)
					}
				}

				testPacked, _ := test.expectedQuery.PreparedMsg().Pack()
				queryPacked, _ := query.PreparedMsg().Pack()

				if !bytes.Equal(testPacked, queryPacked) {
					t.Error("prepared queries did not match")
				}
			}
		})
	}
}

func TestNameExists_DoesNotExist(t *testing.T) {
	question := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: 1,
	}

	query, err := NewDnsQueryFromQuestions([]dns.Question{question})
	if err != nil {
		t.Fatalf("unexpected error creating question: %v", err)
	}

	resolver := FakeResolver{
		records: map[string]string{},
	}

	exists := query.NameExists(&resolver)
	if exists {
		t.Errorf("name was said to exist, but does not exist")
	}
}

func TestNameExists_ExistsAAAA(t *testing.T) {
	question := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeAAAA,
		Qclass: 1,
	}

	query, err := NewDnsQueryFromQuestions([]dns.Question{question})
	if err != nil {
		t.Fatalf("unexpected error creating question: %v", err)
	}

	resolver := FakeResolver{
		records: map[string]string{
			fmt.Sprintf("example.com.:%d", dns.TypeAAAA): "::1",
		},
	}

	exists := query.NameExists(&resolver)
	if !exists {
		t.Errorf("name was said to not exist, but does exist")
	}
}

func TestNameExists_ExistsA(t *testing.T) {
	question := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeAAAA,
		Qclass: 1,
	}

	query, err := NewDnsQueryFromQuestions([]dns.Question{question})
	if err != nil {
		t.Fatalf("unexpected error creating question: %v", err)
	}

	resolver := FakeResolver{
		records: map[string]string{
			fmt.Sprintf("example.com.:%d", dns.TypeA): "127.0.0.1",
		},
	}

	exists := query.NameExists(&resolver)
	if !exists {
		t.Errorf("name was said to not exist, but does exist")
	}
}

func TestNameExists_ExistsA_and_AAAA(t *testing.T) {
	question := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeAAAA,
		Qclass: 1,
	}

	query, err := NewDnsQueryFromQuestions([]dns.Question{question})
	if err != nil {
		t.Fatalf("unexpected error creating question: %v", err)
	}

	resolver := FakeResolver{
		records: map[string]string{
			fmt.Sprintf("example.com.:%d", dns.TypeA):    "127.0.0.1",
			fmt.Sprintf("example.com.:%d", dns.TypeAAAA): "::1",
		},
	}

	exists := query.NameExists(&resolver)
	if !exists {
		t.Errorf("name was said to not exist, but does exist")
	}
}
