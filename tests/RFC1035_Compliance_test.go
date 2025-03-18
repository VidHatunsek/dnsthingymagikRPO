package tests

import (
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"testing"
	"time"
)

func Test_CorrectlyHandlesHeaders(t *testing.T) {
	// Send a simple DNS query for a known domain
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeA, true)

	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	// Check that the query ID is the same as the request ID
	if response.Header.ID != 1234 { // Replace with the ID used in your request (or dynamic query ID)
		t.Errorf("Expected query ID to be 1234, but got %d", response.Header.ID)
	}

	// Check that the query response (qr) flag is set to 1, meaning it's a response
	if response.Header.Response != true {
		t.Errorf("Expected qr (query/response) flag to be set to 1, but it was 0")
	}

	// Check that the recursion desired (rd) flag is set to 1 in the query
	if response.Header.RecursionDesired != true {
		t.Errorf("Expected rd (recursion desired) flag to be set to 1, but it was 0")
	}

	/*// Check that recursion available (ra) flag is set to 1 in the response (assuming recursion is available)
	if response.Header.RecursionAvailable != true {
		t.Errorf("Expected ra (recursion available) flag to be set to 1, but it was 0")
	}*/

	// Check that the opcode is set to 0 (standard query)
	if response.Header.OpCode != 0 {
		t.Errorf("Expected opcode to be 0 (QUERY), but got %d", response.Header.OpCode)
	}

	// Optionally, check for the other flags and ensure that the query is well-formed
	// (e.g., authority and additional sections should be empty in a standard query with no answer)
	if len(response.Authorities) > 0 {
		t.Errorf("Expected no authority section, but found %d entries", len(response.Authorities))
	}

	if len(response.Additionals) > 0 {
		t.Errorf("Expected no additional section, but found %d entries", len(response.Additionals))
	}
}

func Test_RecursionAvailable(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeA, true)
	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}
	if response.Header.RecursionAvailable != true {
		t.Errorf("Expected recursion available to 1, but got 0")
	}
}

func Test_CorrectlyFormatsSections(t *testing.T) {
	// Send a DNS query for a known domain (e.g., "govekar.net")
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeA, true)

	// Test that the answer section is properly populated with an A record
	if len(response.Answers) == 0 {
		t.Error("Expected at least one answer, but got none")
	} else {
		// Check that the answer is an A record (IPv4 address)
		for _, ans := range response.Answers {
			if ans.Header.Type != dnsmessage.TypeA {
				t.Errorf("Expected answer type to be A, but got %d", ans.Header.Type)
			}

		}
	}

	// Test the authority section, which should contain authoritative name server records if the server is authoritative
	if len(response.Authorities) > 0 && response.Header.Authoritative {
		// Ensure that the authority section contains NS (Name Server) records
		for _, auth := range response.Authorities {
			if auth.Header.Type != dnsmessage.TypeNS {
				t.Errorf("Expected authority record type to be NS, but got %d", auth.Header.Type)
			}

		}
	} else if response.Header.Authoritative {
		t.Log("No authority section found (expected if server is authoritative)")
	}

	// Test the additional section, which should contain A records for the name servers listed in the authority section
	if len(response.Additionals) > 0 {
		for _, add := range response.Additionals {
			if add.Header.Type != dnsmessage.TypeA {
				t.Errorf("Expected additional section record type to be A, but got %d", add.Header.Type)
			}

		}
	}

	// Verify if the additional section corresponds to the authority section, i.e., if NS records are followed by A records
	for _, auth := range response.Authorities {
		nsRecord := auth.Body.(*dnsmessage.NSResource).NS
		if nsRecord.String() != "" {
			found := false
			for _, add := range response.Additionals {
				if add.Header.Type == dnsmessage.TypeA {
					// Check if the additional A record corresponds to the NS record
					if add.Header.Name == nsRecord {
						found = true
						break
					}
				}
			}
			if !found {
				t.Errorf("No corresponding A record found in additional section for NS record %s", nsRecord)
			}
		}
	}
}

func Test_ARecord(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeA, true)

	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	found := false
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypeA {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected A record in response")
	}
}

// Test AAAA Record (IPv6)
func Test_AAAARecord(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "google.com.", dnsmessage.TypeAAAA, true)

	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	found := false
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypeAAAA {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected AAAA record in response")
	}
}

// Test CNAME Record
func Test_CNAMERecordResolution(t *testing.T) {
	// Send a DNS query for the A record of the alias
	response := sendDNSQuery(t, "127.0.0.1:53", "www.govekar.net.", dnsmessage.TypeA, true)

	// Check if the response code indicates success
	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	// Verify that the response contains at least one A record
	found := false
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypeA {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected at least one A record in the response")
	}
}

// Test MX Record
func Test_MXRecord(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeMX, true)

	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	found := false
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypeMX {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected MX record in response")
	}
}

// Test NS Record
func Test_NSRecord(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeNS, true)

	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	found := false
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypeNS {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected NS record in response")
	}
}

// Test TXT Record
func Test_TXTRecord(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeTXT, true)

	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	found := false
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypeTXT {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected TXT record in response")
	}
}

// Test PTR Record (Reverse DNS)
func Test_PTRRecord(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "4.3.2.1.in-addr.arpa.", dnsmessage.TypePTR, true)

	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	found := false
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypePTR {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected PTR record in response")
	}
}

// Test SOA Record
func Test_SOARecord(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeSOA, true)

	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("Expected RCODE 0 (NoError), got %d", response.Header.RCode)
	}

	found := false
	for _, ans := range response.Answers {
		if ans.Header.Type == dnsmessage.TypeSOA {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected SOA record in response")
	}
}

/*// Test Recursive Queries
func Test_RecursiveQuery(t *testing.T) {
	server := startTestServer(t)
	defer server.Close()

	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeA)

	if !response.Header.RecursionAvailable {
		t.Errorf("Expected RA (Recursion Available) flag to be set")
	}
}

// Test Iterative Queries (If server is authoritative)
func Test_IterativeQuery(t *testing.T) {
	server := startTestServer(t)
	defer server.Close()

	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeA)

	if response.Header.RecursionAvailable {
		t.Errorf("Server should not allow recursion for iterative queries")
	}
}*/

// Test NXDOMAIN Response (Non-existent domain)
func Test_NXDOMAIN(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "nonexistent.govekar.net.", dnsmessage.TypeA, true)

	if response.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("Expected NXDOMAIN (RCODE 3), got %d", response.Header.RCode)
	}
}

/*// Test SERVFAIL Response (Server failure)
func Test_SERVFAIL(t *testing.T) {
	server := startTestServer(t)
	defer server.Close()

	// Simulating a server error (invalid domain)
	response := sendDNSQuery(t, "127.0.0.1:53", "serverfail.govekar.net.", dnsmessage.TypeA)

	if response.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("Expected SERVFAIL (RCODE 2), got %d", response.Header.RCode)
	}
}

// Test REFUSED Response (Query refused)
func Test_REFUSED(t *testing.T) {
	server := startTestServer(t)
	defer server.Close()

	// Assuming server is configured to refuse certain domains
	response := sendDNSQuery(t, "127.0.0.1:53", "forbidden.govekar.net.", dnsmessage.TypeA)

	if response.Header.RCode != dnsmessage.RCodeRefused {
		t.Errorf("Expected REFUSED (RCODE 5), got %d", response.Header.RCode)
	}
}*/

func Test_WildcardQuery_NoWildcardRecord(t *testing.T) {
	// Query a non-existent subdomain without a wildcard record
	response := sendDNSQuery(t, "127.0.0.1:53", "random.govekar.net.", dnsmessage.TypeA, true)

	// The response should be NXDOMAIN (Non-Existent Domain) if there's no wildcard
	if response.Header.RCode != dnsmessage.RCodeNameError {
		t.Errorf("Expected NXDOMAIN, but got RCode: %v", response.Header.RCode)
	}
}

func Test_WildcardQuery_WithWildcardRecord(t *testing.T) {
	// Query a non-existent subdomain but one that should match the wildcard
	response := sendDNSQuery(t, "127.0.0.1:53", "random.test.govekar.net.", dnsmessage.TypeA, true)

	// The response should return the IP defined by the wildcard record
	if len(response.Answers) == 0 || response.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 168, 1, 1} {
		t.Errorf("Expected IP address from wildcard record, but got: %v", response.Answers)
	}
}

// Test Caching Mechanism
func Test_CacheTTLExpiration(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()
	// First query to cache the record
	response1 := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeA, false)
	initialTTL := response1.Answers[0].Header.TTL
	if initialTTL < 1 {
		t.Errorf("TTL should be greater than 0")
	}

	// Wait for a short duration before expiration (e.g., 1/2 of TTL)
	waitDuration := time.Duration(initialTTL/2) * time.Second
	time.Sleep(waitDuration)

	// Send the second query
	response2 := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.TypeA, false)
	decreasedTTL := response2.Answers[0].Header.TTL

	// Verify that the TTL has decreased (it should be lower than the initial TTL)
	if decreasedTTL >= initialTTL {
		t.Errorf("Expected TTL to decrease, but it didn't. Initial TTL: %d, Decreased TTL: %d", initialTTL, decreasedTTL)
	}

	// Ensure the TTL is still positive after the decrease
	if decreasedTTL <= 0 {
		t.Errorf("TTL should be greater than 0, but it is: %d", decreasedTTL)
	}
}

// Test Malformed Query (Should return FORMAT ERROR)
func Test_MalformedQuery(t *testing.T) {
	s := startTestServer(t)
	defer s.Close()
	// Sending invalid query data
	conn, err := net.Dial("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("Failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	// Set a timeout for the connection to avoid infinite waiting
	err = conn.SetDeadline(time.Now().Add(5 * time.Second)) // Timeout after 5 seconds
	if err != nil {
		t.Fatalf("Failed to set timeout for connection: %v", err)
	}

	// Sending an invalid DNS query (malformed)
	_, err = conn.Write([]byte{0x00, 0x01, 0x02}) // Invalid DNS query format
	if err != nil {
		t.Fatalf("Failed to send malformed query: %v", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		// Check for timeout error (or any other read error)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("Timeout waiting for response from DNS server: %v", err)
		} else {
			t.Fatalf("Failed to read DNS response: %v", err)
		}
	}

	var response dnsmessage.Message
	err = response.Unpack(buf[:n])
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Check if the server returned the correct format error (RCODE 1)
	if response.Header.RCode != dnsmessage.RCodeFormatError {
		t.Errorf("Expected FORMAT ERROR (RCODE 1), got %d", response.Header.RCode)
	}
}

// Test Unknown Record Type Handling
func Test_UnknownRecordType(t *testing.T) {
	response := sendDNSQuery(t, "127.0.0.1:53", "govekar.net.", dnsmessage.Type(99), true) // Unknown type

	if response.Header.RCode != dnsmessage.RCodeNotImplemented {
		t.Errorf("Expected NOTIMPLEMENTED (RCODE 4), got %d", response.Header.RCode)
	}
}
