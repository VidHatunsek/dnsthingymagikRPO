package resolver

import (
	"dnsthingymagik/resolver/query"
	"golang.org/x/net/dns/dnsmessage"
	"log"
	"net"
	"strings"
)

func ResolveDN(domainName string, id uint16, rtype dnsmessage.Type) ([]net.IP, error) {
	ROOT_SERVERS := []string{
		"198.41.0.4",
	}

	result, err := resolveFromRoot(domainName, id, rtype, ROOT_SERVERS)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func resolveFromRoot(domainName string, id uint16, rtype dnsmessage.Type, ROOT_SERVERS []string) ([]net.IP, error) {
	var IPs []net.IP

	if !strings.HasSuffix(domainName, ".") {
		domainName += "."
	}

	for _, root_server := range ROOT_SERVERS {

		q := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               id,
				RecursionDesired: true, // Ensure we don't depend on external recursion
			},
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName(domainName),
					Type:  rtype,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		response, err := query.SendQuery(root_server, q)
		if err != nil {
			return nil, err
		}

		NSIPmap := make(map[string]net.IP)
		var NSs []string

		for _, answer := range response.Answers {
			if answer.Header.Type == dnsmessage.TypeA && response.Header.Authoritative {
				NSs = append(NSs, answer.Header.Name.String())
				IPs = append(IPs, answer.Body.(*dnsmessage.AResource).A[:])
			} else if answer.Header.Type == dnsmessage.TypeNS {
				NSs = append(NSs, answer.Header.Name.String())
			}
		}

		for _, authority := range response.Authorities {
			if authority.Header.Type == dnsmessage.TypeNS {
				NSs = append(NSs, authority.Header.Name.String())
			}
		}

		for _, additional := range response.Additionals {
			if additional.Header.Type == dnsmessage.TypeA {
				ip := additional.Body.(*dnsmessage.AResource).A[:]
				if ip != nil {
					NSIPmap[additional.Header.Name.String()] = ip
				}
			}
		}

		if len(IPs) > 0 && response.Header.Authoritative {
			return IPs, nil
		}

		//resolve from refferal
		for nameserver, nsip := range NSIPmap {
			if nsip == nil {
				nsips, err := ResolveDN(nameserver, id, dnsmessage.TypeA) // resolve nameserver if no ip
				nsip = nsips[0]
				if err != nil || len(nsip) == 0 {
					log.Printf("DNS server %s not resolved: %s", nameserver, err)
					continue
				}

				NSIPmap[nameserver] = nsip
			}

			ip, err := resolveFromRefferal(domainName, id, dnsmessage.TypeA, nsip.String()) // resolve refferal using nameserver
			if err != nil {
				log.Printf("DNS server %s not resolving domain %s: %s", nameserver, domainName, err)
				continue
			}

			IPs = append(IPs, ip[0])
			break
		}
	}

	return IPs, nil
}

func resolveFromRefferal(domainName string, id uint16, rtype dnsmessage.Type, server string) ([]net.IP, error) {
	if !strings.HasSuffix(domainName, ".") {
		domainName += "."
	}

	q := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true, // Ensure we don't depend on external recursion
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domainName),
				Type:  rtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	response, err := query.SendQuery(server, q)
	if err != nil {
		return nil, err
	}

	var IPs []net.IP
	NSIPmap := make(map[string]net.IP)

	for _, answer := range response.Answers {
		if answer.Header.Type == dnsmessage.TypeA && response.Header.Authoritative {
			IPs = append(IPs, answer.Body.(*dnsmessage.AResource).A[:])
		} else if answer.Header.Type == dnsmessage.TypeNS {
			NSIPmap[answer.Body.(*dnsmessage.NSResource).NS.String()] = nil
		}
	}

	for _, authority := range response.Authorities {
		if authority.Header.Type == dnsmessage.TypeNS {
			NSIPmap[authority.Body.(*dnsmessage.NSResource).NS.String()] = nil
		}
	}

	for _, additional := range response.Additionals {
		if additional.Header.Type == dnsmessage.TypeA {
			NSIPmap[additional.Header.Name.String()] = additional.Body.(*dnsmessage.AResource).A[:]
		}
	}

	if len(IPs) > 0 && response.Header.Authoritative {
		return IPs, nil
	}

	for nameserver, nsip := range NSIPmap {
		if nsip == nil {
			nsips, err := ResolveDN(nameserver, id, dnsmessage.TypeA) // resolve nameserver if no ip
			nsip = nsips[0]
			if err != nil || len(nsip) == 0 {
				log.Printf("DNS server %s not resolved: %s", nameserver, err)
				continue
			}

			NSIPmap[nameserver] = nsip
		}

		ip, err := resolveFromRefferal(domainName, id, dnsmessage.TypeA, nsip.String()) // resolve refferal using nameserver
		if err != nil {
			log.Printf("DNS server %s not resolving domain %s: %s", nameserver, domainName, err)
			continue
		}

		IPs = append(IPs, ip[0])
		break
	}

	return IPs, nil
}

//func ProcessDNSResponse(res dnsmessage.Message) ([]net.IP, []dnsmessage.Resource, map[string]net.IP, string, error) {
//	if res.Header.RCode != dnsmessage.RCodeSuccess {
//		return []net.IP{}, []dnsmessage.Resource{}, make(map[string]net.IP), "", fmt.Errorf("DNS q failed with RCode %d", res.Header.RCode)
//	}
//
//	ips := []net.IP{}
//	nameservers := []dnsmessage.Resource{}
//	nsIPMap := make(map[string]net.IP)
//	var cnameTarget string
//
//	for _, ans := range res.Answers {
//		switch ans.Header.Type {
//		case dnsmessage.TypeA:
//			ips = append(ips, ans.Body.(*dnsmessage.AResource).A[:])
//		case dnsmessage.TypeCNAME:
//			cnameTarget = ans.Body.(*dnsmessage.CNAMEResource).CNAME.String()
//		}
//	}
//
//	for _, authority := range res.Authorities {
//		if _, ok := authority.Body.(*dnsmessage.NSResource); ok {
//			nameservers = append(nameservers, authority)
//		}
//
//		if a, ok := authority.Body.(*dnsmessage.AResource); ok {
//			nsIPMap[authority.Header.Name.String()] = net.IP(a.A[:])
//		}
//	}
//
//	for _, additional := range res.Additionals {
//		if additional.Header.Type == dnsmessage.TypeA {
//			nsName := additional.Header.Name.String()
//			nsIP := additional.Body.(*dnsmessage.AResource).A[:]
//			nsIPMap[nsName] = nsIP
//		}
//	}
//
//	return ips, nameservers, nsIPMap, cnameTarget, nil
//
//}
//
//func ResolveDN(domainName string, id uint16, rtype dnsmessage.Type) ([]net.IP, error) {
//	return resolveRecursive(domainName, id, rtype, 0, map[string]bool{})
//}
//
//func resolveRecursive(domainName string, id uint16, rtype dnsmessage.Type, depth int, queriedNS map[string]bool) ([]net.IP, error) {
//	if depth > 5 {
//		return nil, fmt.Errorf("maximum recursion depth reached for %s", domainName)
//	}
//
//	servers := []string{"198.41.0.4"} // Root server
//
//	if !strings.HasSuffix(domainName, ".") {
//		domainName += "."
//	}
//
//	for {
//		var nextServers []string
//		queryFailed := true // Track if all queries fail
//
//		for _, server := range servers {
//			if queriedNS[server] {
//				continue // Don't re-query same NS
//			}
//			queriedNS[server] = true
//
//			q := dnsmessage.Message{
//				Header: dnsmessage.Header{
//					ID:               id,
//					RecursionDesired: true, // Ensure we don't depend on external recursion
//				},
//				Questions: []dnsmessage.Question{
//					{
//						Name:  dnsmessage.MustNewName(domainName),
//						Type:  rtype,
//						Class: dnsmessage.ClassINET,
//					},
//				},
//			}
//
//			res, err := query.SendQuery(server, q)
//			if err != nil {
//				fmt.Printf("Query to %s failed: %v\n", server, err)
//				continue // Try next server
//			}
//
//			ips, nameservers, nsIPmap, cnameTarget, err := ProcessDNSResponse(res)
//			if err != nil {
//				fmt.Printf("Error processing response: %v\n", err)
//				continue
//			}
//
//			if len(ips) > 0 {
//				return ips, nil // Success
//			}
//
//			if cnameTarget != "" {
//				fmt.Printf("Following CNAME: %s → %s\n", domainName, cnameTarget)
//				return resolveRecursive(cnameTarget, id, rtype, depth+1, queriedNS)
//			}
//
//			for _, ns := range nameservers {
//				nsDomain := ns.Body.(*dnsmessage.NSResource).NS.String()
//
//				// Check for glue records
//				if nsIP, found := nsIPmap[nsDomain]; found {
//					fmt.Printf("Using glue record: %s → %s\n", nsDomain, nsIP)
//					nextServers = append(nextServers, nsIP.String())
//					continue
//				} else {
//					fmt.Printf("Resolving NS: %s\n", nsDomain)
//					nsIPs, err := resolveRecursive(nsDomain, id, dnsmessage.TypeA, depth+1, queriedNS)
//					if err != nil {
//						fmt.Printf("Failed to resolve NS %s: %v\n", nsDomain, err)
//						continue
//					}
//
//					for _, nsIP := range nsIPs {
//						fmt.Printf("Resolved NS %s → %s\n", nsDomain, nsIP)
//						nextServers = append(nextServers, nsIP.String())
//					}
//				}
//
//			}
//
//			if len(nextServers) > 0 {
//				servers = nextServers
//				queryFailed = false
//				break
//			}
//		}
//
//		if len(nextServers) == 0 || queryFailed {
//			return nil, fmt.Errorf("failed to resolve %s", domainName)
//		}
//	}
//}
