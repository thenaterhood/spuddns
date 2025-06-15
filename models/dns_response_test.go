package models

import (
	"bytes"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func ttlAreAboutEqual(first uint32, second uint32) bool {
	if math.Round(float64(first)) == math.Round(float64(second)) {
		return true
	}

	if first > second {
		return first-second <= 1
	}

	if second > first {
		return second-first <= 1
	}

	return false
}

func TestNewResponse(t *testing.T) {

	type test struct {
		inputMsg         *dns.Msg
		expectedError    error
		expectedResponse *DnsResponse
		name             string
	}

	invalidMsg := new(dns.Msg)
	invalidMsg.Rcode = 255 // invalid if extended fields are not set

	validMsg := new(dns.Msg)
	validMsg.Rcode = dns.RcodeSuccess
	answer := DNSAnswer{
		Name: "example.com.",
		Type: dns.TypeA,
		TTL:  30 * time.Second,
		Data: "127.0.0.1",
	}
	rr, _ := answer.ToRR()
	validMsg.Answer = append(validMsg.Answer, rr)

	tests := []test{
		{
			inputMsg:         nil,
			expectedError:    nil,
			expectedResponse: &DnsResponse{msg: new(dns.Msg)},
			name:             "nil message does not break",
		},
		{
			inputMsg:         new(dns.Msg),
			expectedError:    nil,
			expectedResponse: &DnsResponse{msg: new(dns.Msg)},
			name:             "empty message does not break",
		},
		{
			inputMsg:         invalidMsg,
			expectedError:    dns.ErrExtendedRcode,
			expectedResponse: nil,
			name:             "invalid message returns error",
		},
		{
			inputMsg:         validMsg,
			expectedError:    nil,
			expectedResponse: &DnsResponse{msg: validMsg},
			name:             "valid message returns expected response",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := NewDnsResponseFromMsg(test.inputMsg)

			if err != test.expectedError {
				t.Errorf("got wrong error for input. actual = '%v', expected = '%v'", err, test.expectedError)
			}

			if !response.Equal(test.expectedResponse) {
				t.Errorf("got wrong response for input. actual = '%v', expected = '%v'", response, test.expectedResponse)
			}

			if test.expectedResponse != nil {
				actualAnswers, _ := response.Answers()
				expectedAnswers, _ := test.expectedResponse.Answers()
				if len(actualAnswers) != len(expectedAnswers) {
					t.Errorf(
						"response had wrong number of answers: expected = %d, actual = %d",
						len(expectedAnswers),
						len(actualAnswers),
					)
				}

				now := time.Now().Add(time.Duration(30 * time.Second))
				test.expectedResponse.Expires = now
				response.Expires = now

				testPacked, _ := test.expectedResponse.AsReplyToMsg(new(dns.Msg)).Pack()
				queryPacked, _ := response.AsReplyToMsg(new(dns.Msg)).Pack()

				if !bytes.Equal(testPacked, queryPacked) {
					t.Error("prepared queries did not match")
				}
			}
		})
	}
}

func TestAddsCNAMEForExpandedSearchDomain(t *testing.T) {
	originalQuery := new(dns.Msg)
	originalQuery.Question = []dns.Question{
		{
			Name:  "example.",
			Qtype: 1,
		},
	}

	expandedMsg := new(dns.Msg)
	expandedMsg.Rcode = dns.RcodeSuccess
	expandedMsgAnswer := DNSAnswer{
		Name: "example.test.local.",
		Type: dns.TypeA,
		TTL:  30 * time.Second,
		Data: "127.0.0.1",
	}
	rr, _ := expandedMsgAnswer.ToRR()
	expandedMsg.Answer = append(expandedMsg.Answer, rr)

	expectedResponseMsg := new(dns.Msg)
	expandedMsg.Question = originalQuery.Question
	expectedResponseMsg.Rcode = dns.RcodeSuccess
	expandedMsgAnswerCname := DNSAnswer{
		Name: "example.",
		Type: dns.TypeCNAME,
		TTL:  30 * time.Second,
		Data: "example.test.local.",
	}
	cnameRr, _ := expandedMsgAnswerCname.ToRR()
	// Deliberately the same RR as above
	expectedResponseMsg.Answer = append(expectedResponseMsg.Answer, cnameRr, rr)

	beforeCname, err := NewDnsResponseFromMsg(expandedMsg)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	responseMsg := beforeCname.AsReplyToMsg(originalQuery)

	if slices.Equal(responseMsg.Answer, expectedResponseMsg.Answer) {
		t.Errorf("CNAME was not added properly")
	}
}

func TestDoesNotAddDupeCNAMEForExpandedSearchDomain(t *testing.T) {
	originalQuery := new(dns.Msg)
	originalQuery.Question = []dns.Question{
		{
			Name:  "example.",
			Qtype: 1,
		},
	}

	expandedMsg := new(dns.Msg)
	expandedMsg.Rcode = dns.RcodeSuccess
	expandedMsgAnswer := DNSAnswer{
		Name: "example.test.local.",
		Type: dns.TypeA,
		TTL:  30 * time.Second,
		Data: "127.0.0.1",
	}
	rr, _ := expandedMsgAnswer.ToRR()
	expandedMsg.Answer = append(expandedMsg.Answer, rr)

	expandedMsgAnswerCname := DNSAnswer{
		Name: "example.",
		Type: dns.TypeCNAME,
		TTL:  30 * time.Second,
		Data: "example.test.local.",
	}
	cnameRr, _ := expandedMsgAnswerCname.ToRR()

	expandedMsg.Answer = append(expandedMsg.Answer, cnameRr)

	expectedResponseMsg := new(dns.Msg)
	expandedMsg.Question = originalQuery.Question
	expectedResponseMsg.Rcode = dns.RcodeSuccess

	// Deliberately the same RR as above
	expectedResponseMsg.Answer = append(expectedResponseMsg.Answer, cnameRr, rr)

	beforeCname, err := NewDnsResponseFromMsg(expandedMsg)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	responseMsg := beforeCname.AsReplyToMsg(originalQuery)

	if slices.Equal(responseMsg.Answer, expectedResponseMsg.Answer) {
		t.Errorf("CNAME was not added properly")
	}
}

func TestGetTtlFromMsg(t *testing.T) {
	validMsg := new(dns.Msg)
	validMsg.Rcode = dns.RcodeSuccess
	answer := DNSAnswer{
		Name: "example.com.",
		Type: dns.TypeA,
		TTL:  30 * time.Second,
		Data: "127.0.0.1",
	}
	rr, _ := answer.ToRR()
	validMsg.Answer = append(validMsg.Answer, rr)

	response, err := NewDnsResponseFromMsg(validMsg)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	if !ttlAreAboutEqual(uint32(response.GetTtl().Seconds()), 30) {
		t.Errorf("TTL did not match message expected = 30, actual = %f", response.GetTtl().Seconds())
	}
}

func TestGetTtlFromEmptyMsg(t *testing.T) {
	validMsg := new(dns.Msg)
	validMsg.Rcode = dns.RcodeSuccess

	response, err := NewDnsResponseFromMsg(validMsg)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	if !ttlAreAboutEqual(uint32(response.GetTtl().Seconds()), 0) {
		t.Errorf("TTL did not match message expected = 0, actual = %f", response.GetTtl().Seconds())
	}
}

func TestGetTtlFromNilMsg(t *testing.T) {
	response, err := NewDnsResponseFromMsg(nil)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	if !ttlAreAboutEqual(uint32(response.GetTtl().Seconds()), 0) {
		t.Errorf("TTL did not match message expected = 0, actual = %f", response.GetTtl().Seconds())
	}
}

func TestGetTtlFromAnswers(t *testing.T) {
	answer := DNSAnswer{
		Name: "example.com.",
		Type: dns.TypeA,
		TTL:  30 * time.Second,
		Data: "127.0.0.1",
	}

	response, err := NewDnsResponseFromDnsAnswers([]DNSAnswer{answer})
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	if !ttlAreAboutEqual(uint32(response.GetTtl().Seconds()), 30) {
		t.Errorf("TTL did not match message expected = 30, actual = %f", response.GetTtl().Seconds())
	}

	preparedMsg := response.AsReplyToMsg(new(dns.Msg))
	preparedTtl := preparedMsg.Answer[0].Header().Ttl

	if !ttlAreAboutEqual(preparedTtl, 30) {
		t.Errorf("TTL did not match message expected = 30, actual = %d", preparedTtl)
	}
}

func TestSetTtlNoAnswers(t *testing.T) {
	response, err := NewDnsResponseFromMsg(new(dns.Msg))
	if err != nil {
		t.Errorf("unexpected error getting response: %v", err)
	}

	response.SetTtl(30 * time.Second)

	if !ttlAreAboutEqual(uint32(response.GetTtl().Seconds()), 30) {
		t.Errorf("TTL did not match message expected = 30, actual = %f", response.GetTtl().Seconds())
	}
}

func TestSetTtlWithAnswers(t *testing.T) {
	validMsg := new(dns.Msg)
	validMsg.Rcode = dns.RcodeSuccess
	answer := DNSAnswer{
		Name: "example.com.",
		Type: dns.TypeA,
		TTL:  10 * time.Second,
		Data: "127.0.0.1",
	}
	rr, _ := answer.ToRR()
	validMsg.Answer = append(validMsg.Answer, rr)

	response, err := NewDnsResponseFromMsg(validMsg)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	if !ttlAreAboutEqual(uint32(response.GetTtl().Seconds()), 10) {
		t.Errorf("TTL did not match message expected = 10, actual = %f", response.GetTtl().Seconds())
	}

	msg := response.AsReplyToMsg(new(dns.Msg))
	msgTtl := msg.Answer[0].Header().Ttl
	if !ttlAreAboutEqual(msgTtl, 10) {
		t.Errorf("Reply dns.Msg has the wrong TTL before manipulation, expected = 10, actual = %d", msgTtl)
	}

	response.SetTtl(30 * time.Second)
	if !ttlAreAboutEqual(uint32(response.GetTtl().Seconds()), 30) {
		t.Errorf("TTL did not match message expected = 30, actual = %f", response.GetTtl().Seconds())
	}

	msg = response.AsReplyToMsg(new(dns.Msg))
	msgTtl = msg.Answer[0].Header().Ttl
	if !ttlAreAboutEqual(msgTtl, 30) {
		t.Errorf("Reply dns.Msg has the wrong TTL after manipulation, expected = 30, actual = %d", msgTtl)
	}
}
