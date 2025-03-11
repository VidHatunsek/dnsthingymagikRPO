package main

import (
	"dnsthingymagik/resolver"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"log"
	"net"
)

func main() {
	udpServer, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	defer udpServer.Close()

	for {
		buf := make([]byte, 514)
		n, addr, err := udpServer.ReadFrom(buf)
		if err != nil {
			log.Println(err)
		}
		go process(udpServer, addr, buf[:n])
	}
}

func process(udp net.PacketConn, addr net.Addr, buf []byte) {
	msg, err := resolver.PacketParser(buf)
	if err != nil {
		log.Println(err)
	}

	faq := map[dnsmessage.Question]net.IP{}
	for _, q := range msg.Questions {
		if q.Type == dnsmessage.TypeA {
			nips, err := resolver.ResolveDN(q.Name.String(), msg.Header.ID, dnsmessage.TypeA)
			if err != nil {
				log.Println(err)
			}

			if len(nips) == 0 {
				log.Printf("No IP found for %s", q.Name.String())
				continue
			}

			faq[q] = nips[0]
		}
	}

	answers := []dnsmessage.Resource{}
	for _, q := range msg.Questions {
		ip, found := faq[q]
		if !found {
			log.Printf("No answer for %s, skipping...", q.Name.String())
			continue
		}

		fmt.Println(ip)

		answers = append(answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   300, //TODO
			},
			Body: &dnsmessage.AResource{
				A: [4]byte{ip[0], ip[1], ip[2], ip[3]},
			},
		})
	}

	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 msg.Header.ID,
			Response:           true,
			OpCode:             msg.Header.OpCode,
			Authoritative:      false,
			RecursionDesired:   msg.Header.RecursionDesired,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: msg.Questions,
		Answers:   answers,
	}

	fmt.Println(response)

	packed, err := response.Pack()
	if err != nil {
		log.Println(err)
	}

	_, err = udp.WriteTo(packed, addr)
	if err != nil {
		return
	}
}
