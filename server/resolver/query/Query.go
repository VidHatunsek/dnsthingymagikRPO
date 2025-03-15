package query

import (
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"time"
)

func SendQuery(server string, query dnsmessage.Message) (dnsmessage.Message, error) {
	conn, err := net.DialTimeout("udp", server+":53", 5*time.Second)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()

	q, err := query.Pack()
	if err != nil {
		return dnsmessage.Message{}, err
	}

	_, err = conn.Write(q)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	buf := make([]byte, 512)
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return dnsmessage.Message{}, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	msg := dnsmessage.Message{}
	err = msg.Unpack(buf[:n])
	if err != nil {
		return dnsmessage.Message{}, err
	}

	return msg, nil
}
