package resolver

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"log/slog"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
)

func startUDPTruncResponder(t *testing.T, port int) (net.PacketConn, chan struct{}) {
	pc, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to start udp listener: %v", err)
	}
	done := make(chan struct{})

	go func() {
		defer pc.Close()
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}

			pc.SetDeadline(time.Now().Add(200 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}

			var req dns.Msg
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}

			rep := new(dns.Msg)
			rep.SetReply(&req)
			rep.Truncated = true

			packed, err := rep.Pack()
			if err != nil {
				continue
			}

			_, _ = pc.WriteTo(packed, addr)
		}
	}()

	return pc, done
}

func startTCPResponder(t *testing.T, port int) (net.Listener, chan struct{}) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to start tcp listener: %v", err)
	}
	done := make(chan struct{})

	go func() {
		defer ln.Close()
		for {
			ln.(*net.TCPListener).SetDeadline(time.Now().Add(200 * time.Millisecond))
			conn, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 2)
				if _, err := c.Read(lenBuf); err != nil {
					return
				}
				l := int(binary.BigEndian.Uint16(lenBuf))
				msgBuf := make([]byte, l)
				if _, err := c.Read(msgBuf); err != nil {
					return
				}

				var req dns.Msg
				if err := req.Unpack(msgBuf); err != nil {
					return
				}

				rep := new(dns.Msg)
				rep.SetReply(&req)
				a := &dns.A{
					Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("203.0.113.5").To4(),
				}
				rep.Answer = append(rep.Answer, a)

				packed, err := rep.Pack()
				if err != nil {
					return
				}

				outLen := make([]byte, 2)
				binary.BigEndian.PutUint16(outLen, uint16(len(packed)))
				_, _ = c.Write(outLen)
				_, _ = c.Write(packed)
			}(conn)
		}
	}()

	return ln, done
}

func TestUDPTruncationFallbackToTCP(t *testing.T) {
	udpLn, udpDone := startUDPTruncResponder(t, 0)
	defer func() {
		close(udpDone)
		udpLn.Close()
	}()

	udpAddr := udpLn.LocalAddr().(*net.UDPAddr)
	udpPort := udpAddr.Port

	tcpLn, tcpDone := startTCPResponder(t, udpPort)
	defer func() {
		close(tcpDone)
		tcpLn.Close()
	}()

	serverHost := fmt.Sprintf("127.0.0.1:%d", udpPort)

	q, err := models.NewDnsQueryFromQuestions([]dns.Question{
		{
			Name:   "example.com.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	})
	if err != nil {
		t.Fatalf("failed to build dns query: %v", err)
	}

	mdc := miekgDnsClient{
		clientConfig: DnsResolverConfig{
			Servers: []string{serverHost},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.Level(slog.LevelDebug)})),
			Metrics: &metrics.DummyMetrics{},
			Timeout: 2,
			Mdns:    NewDefaultMdnsConfig(),
		},
	}

	resp, err := mdc.QueryDns(*q)
	if err != nil {
		t.Fatalf("QueryDns returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected a response, got nil")
	}

	answers, aerr := resp.Answers()
	if aerr != nil {
		t.Fatalf("failed to get answers from response: %v", aerr)
	}
	if len(answers) == 0 {
		t.Fatalf("expected at least one answer after tcp fallback, got none")
	}

	if answers[0].Data != "203.0.113.5" {
		t.Fatalf("unexpected answer data: %v", answers[0].Data)
	}
}
