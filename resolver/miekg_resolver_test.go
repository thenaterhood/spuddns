package resolver

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/thenaterhood/spuddns/metrics"
	"github.com/thenaterhood/spuddns/models"
)

func startDualStackServer(t *testing.T, port int) (net.PacketConn, net.Listener, chan struct{}) {
	pc, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to start udp listener: %v", err)
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		pc.Close()
		t.Fatalf("failed to start tcp listener: %v", err)
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
				c.Write(outLen)
				c.Write(packed)
			}(conn)
		}
	}()

	return pc, ln, done
}

func getTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestUDPTruncationFallbackToTCP(t *testing.T) {
	udpServer, tcpServer, done := startDualStackServer(t, 15353)
	defer close(done)
	defer udpServer.Close()
	defer tcpServer.Close()

	time.Sleep(10 * time.Millisecond)

	config := DnsResolverConfig{
		Servers: []string{
			"127.0.0.1:15353",
		},
		Logger:          getTestLogger(),
		Metrics:         &metrics.DummyMetrics{},
		Timeout:         5,
		ForceMimimumTtl: 0,
		Mdns:            NewDefaultMdnsConfig(),
	}

	client := NewMiekgDnsClient(config)

	query, err := models.NewDnsQueryFromQuestions([]dns.Question{
		{Name: "example.com.", Qtype: dns.TypeA},
	})
	if err != nil {
		t.Fatalf("failed to create query: %v", err)
	}

	response, err := client.QueryDns(*query)

	if response == nil {
		t.Fatal("expected response but got nil")
	}

	if !response.IsSuccess() {
		t.Fatalf("expected successful response, got rcode: %d", response.Rcode())
	}

	answers, err := response.Answers()
	if err != nil || len(answers) == 0 {
		t.Fatal("expected answers in response after TCP fallback")
	}

	if answers[0].Data != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5, got %s", answers[0].Data)
	}
}

func TestMiekgClientBasic(t *testing.T) {
	udpServer, tcpServer, done := startDualStackServer(t, 15354)
	defer close(done)
	defer udpServer.Close()
	defer tcpServer.Close()

	time.Sleep(10 * time.Millisecond)

	config := DnsResolverConfig{
		Servers: []string{
			"127.0.0.1:15354",
		},
		Logger:          getTestLogger(),
		Metrics:         &metrics.DummyMetrics{},
		Timeout:         5,
		ForceMimimumTtl: 0,
		Mdns:            NewDefaultMdnsConfig(),
	}

	client := NewMiekgDnsClient(config)

	query, err := models.NewDnsQueryFromQuestions([]dns.Question{
		{Name: "test.example.com.", Qtype: dns.TypeA},
	})
	if err != nil {
		t.Fatalf("failed to create query: %v", err)
	}

	response, err := client.QueryDns(*query)

	if response == nil {
		t.Fatal("expected response but got nil")
	}

	if !response.IsSuccess() {
		t.Fatalf("expected successful response, got rcode: %d", response.Rcode())
	}

	answers, err := response.Answers()
	if err != nil || len(answers) == 0 {
		t.Fatal("expected answers in response")
	}

	if answers[0].Data != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5, got %s", answers[0].Data)
	}
}
