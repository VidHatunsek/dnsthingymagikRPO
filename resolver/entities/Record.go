package entities

import (
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"time"
)

type Record struct {
	IP       net.IP
	RType    dnsmessage.Type
	TTL      uint32
	Class    dnsmessage.Class
	Name     dnsmessage.Name
	ExpireAt time.Time
}
