package resolver

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
)

func PacketParser(buf []byte) (dnsmessage.Message, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(buf)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	msg := dnsmessage.Message{
		Header: header,
	}

	for {
		question, err := parser.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}

		if err != nil {
			return dnsmessage.Message{}, err
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
			return dnsmessage.Message{}, err
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
			return dnsmessage.Message{}, err
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
			return dnsmessage.Message{}, err
		}

		msg.Additionals = append(msg.Additionals, additional)
	}

	return msg, nil
}
