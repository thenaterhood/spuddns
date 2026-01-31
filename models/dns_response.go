package models

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type UnsupportedRR struct {
	Code uint16
}

func (m UnsupportedRR) Error() string {
	return fmt.Sprintf("RR type '%d' is unsupported", m.Code)
}

type MalformedRR struct {
	Code uint16
	Msg  string
}

func (m MalformedRR) Error() string {
	return fmt.Sprintf("RR type '%d' with data '%s' is malformed", m.Code, m.Msg)
}

func IsOversizedResponse(dnsResponse *dns.Msg, err error) bool {
	if dnsResponse != nil && dnsResponse.Truncated {
		return true
	}

	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) || errors.Is(err, syscall.ENOBUFS) {
			return true
		}
	}

	return false
}

type DnsResponse struct {
	msg                *dns.Msg // this can't be json marshalled
	Expires            time.Time
	FromCache          bool
	Resolver           string
	RecursionAvailable bool
}

func NewDnsResponseFromMsg(msg *dns.Msg) (*DnsResponse, error) {
	if msg == nil {
		msg = new(dns.Msg)
	}
	response := DnsResponse{
		msg: msg.Copy(),
	}

	if _, err := response.msg.Pack(); err != nil {
		return nil, err // Lazy validation of the message
	}

	ttl := response.GetTtl()
	response.Expires = time.Now().Add(time.Duration(ttl))

	return &response, nil
}

// Construct a DnsResponse from a byte representation of dns.Msg
func NewDnsResponseFromBytes(msg []byte) (*DnsResponse, error) {
	dnsReq := new(dns.Msg)
	if err := dnsReq.Unpack(msg); err != nil {
		return nil, err
	}

	return NewDnsResponseFromMsg(dnsReq)
}

func NewDnsResponseFromDnsAnswers(answers []DNSAnswer) (*DnsResponse, error) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess

	for _, a := range answers {
		rr, err := a.ToRR()
		if err != nil {
			return nil, err
		}
		msg.Answer = append(msg.Answer, rr)
	}

	return NewDnsResponseFromMsg(msg)
}

func NewServFailDnsResponse() *DnsResponse {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeServerFailure
	return &DnsResponse{
		msg: msg,
	}
}

func NewNXDomainDnsResponse() *DnsResponse {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	return &DnsResponse{
		msg: msg,
	}
}

func NewRefusedDnsResponse() *DnsResponse {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeRefused
	return &DnsResponse{
		msg: msg,
	}
}

func NewNoErrorDnsResponse() *DnsResponse {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	return &DnsResponse{
		msg: msg,
	}
}

func (d *DnsResponse) InsertAnswer(answer DNSAnswer) error {
	if d.msg == nil {
		d.msg = new(dns.Msg)
		d.msg.Rcode = dns.RcodeSuccess
	}

	rr, err := answer.ToRR()
	if err != nil {
		return err
	}

	answers := []dns.RR{rr}
	answers = append(answers, d.msg.Answer...)

	d.msg.Answer = answers

	return nil
}

func (d *DnsResponse) ChangeNameFrom(original string, to string, ttl time.Duration) {
	if d.msg == nil {
		d.msg = new(dns.Msg)
		d.msg.Rcode = dns.RcodeSuccess
	}

	cname := DNSAnswer{
		Name: original,
		Type: dns.TypeCNAME,
		TTL:  ttl,
		Data: to,
	}

	if original == to {
		return
	}

	for _, rr := range d.msg.Answer {
		answer, err := NewDnsAnswerFromRR(rr)
		if err != nil {
			continue
		}

		if answer.Type == cname.Type && answer.Data == cname.Data {
			// Already exists, don't add it again
			return
		}
	}

	d.InsertAnswer(cname)
}

func (d *DnsResponse) ChangeName(name string) {
	/**
	 * Alters the name used in the answers. This is
	 * intended to be used to convert a DNS answer from
	 * an expanded name back to the original name.
	 */
	if d.msg != nil {
		if len(d.msg.Answer) > 0 {
			firstAnswer, err := NewDnsAnswerFromRR(d.msg.Answer[0])
			if err != nil {
				return
			}

			if firstAnswer.Name != name && firstAnswer.Type != dns.TypeCNAME {
				d.ChangeNameFrom(name, firstAnswer.Name, firstAnswer.TTL)
			}
		}
	}
}

func (d *DnsResponse) Equal(other *DnsResponse) bool {
	if other == nil && d == nil {
		return true
	}

	if other == nil {
		return false
	}

	if d == nil {
		return false
	}

	packed, _ := d.msg.Pack()
	otherPacked, _ := other.msg.Pack()

	return bytes.Equal(packed, otherPacked)
}

func (d DnsResponse) IsEmpty() bool {
	if d.msg == nil {
		return true
	}
	return len(d.msg.Answer) == 0
}

func (d DnsResponse) IsSuccess() bool {
	if d.msg == nil {
		return false
	}
	return d.msg.Rcode == dns.RcodeSuccess
}

func (d DnsResponse) GetTtl() time.Duration {
	// This isn't strictly correct because each answer
	// has its own TTL, but DNS typically only has one answer
	// anyway

	if !d.Expires.IsZero() {
		return time.Until(d.Expires)
	}

	if d.IsEmpty() {
		return 0
	}

	var ttls []uint32
	for _, answer := range d.msg.Answer {
		ttls = append(ttls, answer.Header().Ttl)
	}

	return time.Duration(slices.Min(ttls)) * time.Second
}

func (d *DnsResponse) SetTtl(ttl time.Duration) {
	d.Expires = time.Now().Add(ttl)
	d.bumpAnswerTTLs()
}

func (d *DnsResponse) bumpAnswerTTLs() {
	ttl := d.GetTtl()
	answers := []dns.RR{}

	if d.msg != nil {
		for _, a := range d.msg.Answer {

			dnsAnswer, err := NewDnsAnswerFromRR(a)
			if err != nil {
				continue
			}

			dnsAnswer.TTL = ttl

			rr, err := dnsAnswer.ToRR()
			if err != nil {
				continue
			}

			answers = append(answers, rr)
		}
	}
	d.msg.Answer = answers
}

func (d DnsResponse) Answers() ([]DNSAnswer, error) {
	answers := []DNSAnswer{}
	if d.msg == nil {
		return answers, nil
	}

	for _, rr := range d.msg.Answer {
		dnsAnswer, err := NewDnsAnswerFromRR(rr)
		if err != nil {
			return answers, err
		}
		dnsAnswer.TTL = d.GetTtl()

		answers = append(answers, *dnsAnswer)
	}

	return answers, nil
}

func (d *DnsResponse) AsReplyToMsg(msg *dns.Msg) *dns.Msg {
	if d.msg == nil {
		return nil
	}

	reply := d.Copy()
	reply.bumpAnswerTTLs()

	query, err := NewDnsQueryFromMsg(msg)
	if err == nil {
		// TODO dont have this be a silent failure
		// This is needed so that clients receive an
		// answer for the host they requested rather
		// than an expanded version with the search
		// domain. Some handle the expanded version
		// but many don't.
		question := query.FirstQuestion()
		if question != nil {
			reply.ChangeName(question.Name)
		}
	}

	resp := new(dns.Msg)
	resp.RecursionAvailable = cmp.Or(reply.RecursionAvailable, reply.Resolver != "")
	resp.SetReply(msg)
	resp.Rcode = reply.msg.Rcode

	if msg != nil {
		resp.Answer = reply.msg.Answer
	}

	return resp
}

func (d *DnsResponse) Copy() DnsResponse {
	resp, _ := NewDnsResponseFromMsg(d.msg)
	resp.FromCache = d.FromCache
	resp.Expires = d.Expires
	resp.Resolver = d.Resolver

	return *resp
}

// DNSAnswer represents a single DNS answer
// A DNS response can *technically* contain multiple
// answers but in practice this doesn't really work
type DNSAnswer struct {
	Name string        `json:"name"`
	Type uint16        `json:"type"`
	TTL  time.Duration `json:"ttl"`
	Data string        `json:"data"`
}

func NewDnsAnswerFromRR(answer dns.RR) (*DNSAnswer, error) {
	hdr := answer.Header()
	dnsAnswer := DNSAnswer{
		Name: hdr.Name,
		Type: hdr.Rrtype,
		TTL:  time.Duration(hdr.Ttl) * time.Second,
	}

	rrText := answer.String()
	typeName, ok := dns.TypeToString[hdr.Rrtype]
	if typeName == "" || !ok {
		typeName = fmt.Sprintf("TYPE%d", hdr.Rrtype)
	}
	prefix := fmt.Sprintf("%s %d IN %s", hdr.Name, hdr.Ttl, typeName)

	if strings.HasPrefix(rrText, prefix) {
		data := strings.TrimSpace(rrText[len(prefix):])
		dnsAnswer.Data = data
		return &dnsAnswer, nil
	}

	// search for RFC3597 marker "\#" or "#" anywhere in the text
	fields := strings.Fields(rrText)
	for i, f := range fields {
		if f == "\\#" || f == "#" {
			dnsAnswer.Data = strings.Join(fields[i:], " ")
			return &dnsAnswer, nil
		}
	}

	// handles some non-canonical string forms.
	parts := strings.Fields(rrText)
	if len(parts) >= 5 {
		dnsAnswer.Data = strings.Join(parts[4:], " ")
		return &dnsAnswer, nil
	}

	return nil, UnsupportedRR{hdr.Rrtype}
}

func (answer DNSAnswer) ToRR() (dns.RR, error) {
	if answer.Name == "" {
		return nil, MalformedRR{answer.Type, "empty name"}
	}

	data := strings.TrimSpace(answer.Data)
	if data == "" {
		return nil, MalformedRR{answer.Type, "empty rdata"}
	}

	ttl := int(answer.TTL.Seconds())

	typeName, ok := dns.TypeToString[answer.Type]
	if ok {
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", answer.Name, ttl, typeName, data))
		if err == nil {
			return rr, nil
		}
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN TYPE%d %s", answer.Name, ttl, answer.Type, data))
	if err == nil {
		return rr, nil
	}

	return nil, MalformedRR{answer.Type, fmt.Sprintf("failed to construct RR from data: %v", err)}
}
