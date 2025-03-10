package resolver

import (
	"dnsthingymagik/resolver/query"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"strings"
)

func ProcessDNSResponse(res dnsmessage.Message) ([]net.IP, []dnsmessage.Name, error) {
	if res.Header.RCode != dnsmessage.RCodeSuccess {
		return []net.IP{}, []dnsmessage.Name{}, fmt.Errorf("DNS q failed with RCode %d", res.Header.RCode)
	}

	ips := []net.IP{}
	nameservers := []dnsmessage.Name{}

	for _, ans := range res.Answers {
		switch ans.Header.Type {
		case dnsmessage.TypeA:
			ips = append(ips, ans.Body.(*dnsmessage.AResource).A[:])
		case dnsmessage.TypeCNAME:
			cname := ans.Body.(*dnsmessage.CNAMEResource).CNAME
			nameservers = append(nameservers, cname)
		}
	}

	for _, authority := range res.Authorities {
		if ns, ok := authority.Body.(*dnsmessage.NSResource); ok {
			nameservers = append(nameservers, ns.NS)
		}
	}
	return ips, nameservers, nil

}

func ResolveDN(domainName string, id uint16) ([]net.IP, error) {
	// TODO CACHE
	servers := []string{
		"198.41.0.4",
	}

	if !strings.HasSuffix(domainName, ".") {
		domainName = domainName + "."
	}

	for {
		for _, server := range servers {
			q := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:               id,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{
					{
						Name:  dnsmessage.MustNewName(domainName),
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
				},
			}

			res, err := query.SendQuery(server, q)
			if err != nil {
				return []net.IP{}, err
			}

			ips, nameservers, err := ProcessDNSResponse(res)
			if err != nil {
				return []net.IP{}, err
			}

			if len(ips) > 0 {
				return ips, nil
			}

			if len(nameservers) > 0 {
				newservers := []string{}
				for _, ns := range nameservers {
					nsIPs, err := ResolveDN(ns.String(), id)
					if err != nil {
						return []net.IP{}, err
					}

					for _, nsIP := range nsIPs {
						newservers = append(newservers, nsIP.String())
					}
				}
				servers = newservers
				break
			}
		}
	}
}
