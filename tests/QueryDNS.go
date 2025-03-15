package tests

import (
	"dnsthingymagik/server"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"testing"
	"time"
)

func sendDNSQuery(t *testing.T, serverAddr, domain string, qType dnsmessage.Type, autostart bool) dnsmessage.Message {
	if autostart {
		s := startTestServer(t)
		defer s.Close()
	}

	t.Helper()

	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	var msg dnsmessage.Message
	msg.Header.ID = 1234
	msg.Header.RecursionDesired = true
	msg.Questions = []dnsmessage.Question{
		{
			Name:  dnsmessage.MustNewName(domain),
			Type:  qType,
			Class: dnsmessage.ClassINET,
		},
	}

	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack DNS query: %v", err)
	}
	_, err = conn.Write(query)
	if err != nil {
		t.Fatalf("Failed to send DNS query: %v", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read DNS response: %v", err)
	}

	var response dnsmessage.Message
	err = response.Unpack(buf[:n])
	if err != nil {
		t.Fatalf("Failed to unpack DNS response: %v", err)
	}

	return response
}

// Setup Test Server
func startTestServer(t *testing.T) *server.Server {
	server, err := server.NewServer(":53")
	if err != nil {
		t.Fatalf("Failed to start DNS server: %v", err)
	}
	go func() { server.Start() }()
	time.Sleep(500 * time.Millisecond) // Allow server to initialize
	return server
}
