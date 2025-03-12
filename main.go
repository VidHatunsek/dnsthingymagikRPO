package main

import (
	"dnsthingymagik/resolver"
	"dnsthingymagik/resolver/entities"
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
	defer func(udpServer net.PacketConn) {
		err := udpServer.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(udpServer)

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

	var faq []entities.Record
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

			faq = append(faq, nips...)
		}
	}

	var answers []dnsmessage.Resource
	for _, record := range faq {
		answers = append(answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  record.Name,
				Type:  record.RType,
				Class: record.Class,
				TTL:   record.TTL,
			},
			Body: &dnsmessage.AResource{
				A: [4]byte{record.IP[0], record.IP[1], record.IP[2], record.IP[3]},
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
