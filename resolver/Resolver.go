package resolver

import (
	"dnsthingymagik/resolver/query"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"strings"
)

func ProcessDNSResponse(res dnsmessage.Message) ([]net.IP, []dnsmessage.Resource, map[string]net.IP, string, error) {
	if res.Header.RCode != dnsmessage.RCodeSuccess {
		return []net.IP{}, []dnsmessage.Resource{}, make(map[string]net.IP), "", fmt.Errorf("DNS q failed with RCode %d", res.Header.RCode)
	}

	ips := []net.IP{}
	nameservers := []dnsmessage.Resource{}
	nsIPMap := make(map[string]net.IP)
	var cnameTarget string

	for _, ans := range res.Answers {
		switch ans.Header.Type {
		case dnsmessage.TypeA:
			ips = append(ips, ans.Body.(*dnsmessage.AResource).A[:])
		case dnsmessage.TypeCNAME:
			cnameTarget = ans.Body.(*dnsmessage.CNAMEResource).CNAME.String()
		}
	}

	for _, authority := range res.Authorities {
		if _, ok := authority.Body.(*dnsmessage.NSResource); ok {
			nameservers = append(nameservers, authority)
		}

		if a, ok := authority.Body.(*dnsmessage.AResource); ok {
			nsIPMap[authority.Header.Name.String()] = net.IP(a.A[:])
		}
	}

	for _, additional := range res.Additionals {
		if additional.Header.Type == dnsmessage.TypeA {
			nsName := additional.Header.Name.String()
			nsIP := additional.Body.(*dnsmessage.AResource).A[:]
			nsIPMap[nsName] = nsIP
		}
	}

	return ips, nameservers, nsIPMap, cnameTarget, nil

}

func ResolveDN(domainName string, id uint16, rtype dnsmessage.Type) ([]net.IP, error) {
	return resolveRecursive(domainName, id, rtype, 0, map[string]bool{})
}

func resolveRecursive(domainName string, id uint16, rtype dnsmessage.Type, depth int, queriedNS map[string]bool) ([]net.IP, error) {
	if depth > 5 {
		return nil, fmt.Errorf("maximum recursion depth reached for %s", domainName)
	}

	servers := []string{"198.41.0.4"} // Root server

	if !strings.HasSuffix(domainName, ".") {
		domainName += "."
	}

	for {
		var nextServers []string
		queryFailed := true // Track if all queries fail

		for _, server := range servers {
			if queriedNS[server] {
				continue // Don't re-query same NS
			}
			queriedNS[server] = true

			q := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:               id,
					RecursionDesired: false, // Ensure we don't depend on external recursion
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName(domainName),
						Type:  rtype,
						Class: dnsmessage.ClassINET,
					},
				},
			}

			res, err := query.SendQuery(server, q)
			if err != nil {
				fmt.Printf("Query to %s failed: %v\n", server, err)
				continue // Try next server
			}

			ips, nameservers, nsIPmap, cnameTarget, err := ProcessDNSResponse(res)
			if err != nil {
				fmt.Printf("Error processing response: %v\n", err)
				continue
			}

			if len(ips) > 0 {
				return ips, nil // Success
			}

			if cnameTarget != "" {
				fmt.Printf("Following CNAME: %s → %s\n", domainName, cnameTarget)
				return resolveRecursive(cnameTarget, id, rtype, depth+1, queriedNS)
			}

			for _, ns := range nameservers {
				nsDomain := ns.Body.(*dnsmessage.NSResource).NS.String()

				// Check for glue records
				if nsIP, found := nsIPmap[nsDomain]; found {
					fmt.Printf("Using glue record: %s → %s\n", nsDomain, nsIP)
					nextServers = append(nextServers, nsIP.String())
					continue
				}

				// Resolve NS name to IP
				fmt.Printf("Resolving NS: %s\n", nsDomain)
				nsIPs, err := resolveRecursive(nsDomain, id, dnsmessage.TypeA, depth+1, queriedNS)
				if err != nil {
					fmt.Printf("Failed to resolve NS %s: %v\n", nsDomain, err)
					continue
				}

				for _, nsIP := range nsIPs {
					fmt.Printf("Resolved NS %s → %s\n", nsDomain, nsIP)
					nextServers = append(nextServers, nsIP.String())
				}
			}

			if len(nextServers) > 0 {
				servers = nextServers
				queryFailed = false
				break
			}
		}

		if len(nextServers) == 0 || queryFailed {
			return nil, fmt.Errorf("failed to resolve %s", domainName)
		}
	}
}
