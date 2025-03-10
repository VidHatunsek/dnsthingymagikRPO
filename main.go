package main

import (
	"dnsthingymagik/cache"
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

	rc := cache.NewRecordsCache()

	for {
		buf := make([]byte, 514)
		n, addr, err := udpServer.ReadFrom(buf)
		if err != nil {
			log.Println(err)
		}
		go process(addr, buf[:n], rc)

		//go response(udpServer, addr, buf)
	}
}

func process(addr net.Addr, buf []byte, rc *cache.RecordsCache) {
	var parser dnsmessage.Parser
	header, err := parser.Start(buf)
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println(header)

	msg := dnsmessage.Message{
		Header: header,
	}

	for {
		question, err := parser.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}

		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		fmt.Println(question)
		msg.Questions = append(msg.Questions, question)
	}

	for {
		answer, err := parser.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}

		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		fmt.Println(answer)
		msg.Answers = append(msg.Answers, answer)
	}

	for {
		authority, err := parser.Authority()
		if err == dnsmessage.ErrSectionDone {
			break
		}

		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		fmt.Println(authority)
		msg.Authorities = append(msg.Authorities, authority)
	}

	for {
		additional, err := parser.Additional()
		if err == dnsmessage.ErrSectionDone {
			break
		}

		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		fmt.Println(additional)
		msg.Additionals = append(msg.Additionals, additional)
	}

	// MESSAGE IS FULL

	fmt.Println(msg)

}
