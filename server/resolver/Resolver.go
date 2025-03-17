package resolver

import (
	"dnsthingymagik/server/recordcache"
	"dnsthingymagik/server/resolver/entities"
	"dnsthingymagik/server/resolver/query"
	"golang.org/x/net/dns/dnsmessage"
	"log"
	"net"
)

func ResolveDN(domainName dnsmessage.Name, id uint16, rtype dnsmessage.Type, cache *recordcache.Cache) ([]entities.Record, error) {
	if recs, found := cache.Get(domainName, dnsmessage.TypeA); found {
		return recs, nil
	}

	ROOT_SERVERS := []string{
		"198.41.0.4",
	}

	result, err := resolveFromRoot(domainName, id, rtype, ROOT_SERVERS, cache)
	if err != nil {
		return nil, err
	}

	for _, rec := range result {
		cache.Set(rec)
	}

	return result, nil
}

func resolveFromRoot(domainName dnsmessage.Name, id uint16, rtype dnsmessage.Type, ROOT_SERVERS []string, cache *recordcache.Cache) ([]entities.Record, error) {
	var records []entities.Record

	for _, rootServer := range ROOT_SERVERS {

		q := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:               id,
				RecursionDesired: true, // Ensure we don't depend on external recursion
			},
			Questions: []dnsmessage.Question{
				{
					Name:  domainName,
					Type:  rtype,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		response, err := query.SendQuery(rootServer, q)
		if err != nil {
			return nil, err
		}

		NSIPmap := make(map[string]net.IP)
		var NSs []string

		for _, answer := range response.Answers {
			if answer.Header.Type == dnsmessage.TypeA && response.Header.Authoritative {
				NSs = append(NSs, answer.Header.Name.String())
				r := entities.Record{
					IP:    answer.Body.(*dnsmessage.AResource).A[:],
					RType: answer.Header.Type,
					TTL:   answer.Header.TTL,
					Class: answer.Header.Class,
					Name:  answer.Header.Name,
				}
				records = append(records, r)
			} else if answer.Header.Type == dnsmessage.TypeNS {
				NSs = append(NSs, answer.Header.Name.String())
			} else if answer.Header.Type == dnsmessage.TypeCNAME {
				cname := answer.Body.(*dnsmessage.CNAMEResource).CNAME
				// Recursively resolve the CNAME target
				cnameRecords, err := ResolveDN(cname, id, rtype, cache)
				if err != nil {
					log.Printf("Failed to resolve CNAME target %s: %v", cname.String(), err)
					continue
				}
				records = append(records, cnameRecords...)
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

		if len(records) > 0 && response.Header.Authoritative {
			return records, nil
		}

		//resolve from refferal
		for nameserver, nsip := range NSIPmap {
			if nsip == nil {
				nsips, err := ResolveDN(dnsmessage.MustNewName(nameserver), id, dnsmessage.TypeA, cache) // resolve nameserver if no ip
				nsip = nsips[0].IP
				if err != nil || len(nsip) == 0 {
					log.Printf("DNS server %s not resolved: %s", nameserver, err)
					continue
				}

				NSIPmap[nameserver] = nsip
			}

			ip, err := resolveFromRefferal(domainName, id, dnsmessage.TypeA, nsip.String(), cache) // resolve refferal using nameserver
			if err != nil {
				log.Printf("DNS server %s not resolving domain %s: %s", nameserver, domainName, err)
				continue
			}

			records = append(records, ip...)
			break
		}
	}

	return records, nil
}

func resolveFromRefferal(domainName dnsmessage.Name, id uint16, rtype dnsmessage.Type, server string, cache *recordcache.Cache) ([]entities.Record, error) {
	q := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true, // Ensure we don't depend on external recursion
		},
		Questions: []dnsmessage.Question{
			{
				Name:  domainName,
				Type:  rtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	response, err := query.SendQuery(server, q)
	if err != nil {
		return nil, err
	}

	var records []entities.Record
	NSIPmap := make(map[string]net.IP)

	for _, answer := range response.Answers {
		if answer.Header.Type == dnsmessage.TypeA && response.Header.Authoritative {
			r := entities.Record{
				IP:    answer.Body.(*dnsmessage.AResource).A[:],
				RType: answer.Header.Type,
				TTL:   answer.Header.TTL,
				Class: answer.Header.Class,
				Name:  answer.Header.Name,
			}
			records = append(records, r)
		} else if answer.Header.Type == dnsmessage.TypeNS {
			NSIPmap[answer.Body.(*dnsmessage.NSResource).NS.String()] = nil
		} else if answer.Header.Type == dnsmessage.TypeCNAME {
			cname := answer.Body.(*dnsmessage.CNAMEResource).CNAME
			// Recursively resolve the CNAME target
			cnameRecords, err := ResolveDN(cname, id, rtype, cache)
			if err != nil {
				log.Printf("Failed to resolve CNAME target %s: %v", cname.String(), err)
				continue
			}
			records = append(records, cnameRecords...)
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

	if len(records) > 0 && response.Header.Authoritative {
		return records, nil
	}

	for nameserver, nsip := range NSIPmap {
		if nsip == nil {
			nsips, err := ResolveDN(dnsmessage.MustNewName(nameserver), id, dnsmessage.TypeA, cache) // resolve nameserver if no ip
			nsip = nsips[0].IP
			if err != nil || len(nsip) == 0 {
				log.Printf("DNS server %s not resolved: %s", nameserver, err)
				continue
			}

			NSIPmap[nameserver] = nsip
		}

		ip, err := resolveFromRefferal(domainName, id, dnsmessage.TypeA, nsip.String(), cache) // resolve refferal using nameserver
		if err != nil {
			log.Printf("DNS server %s not resolving domain %s: %s", nameserver, domainName, err)
			continue
		}

		records = append(records, ip...)
		break
	}

	return records, nil
}
