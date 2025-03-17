package server

import (
	"context"
	"dnsthingymagik/server/recordcache"
	"dnsthingymagik/server/resolver"
	"dnsthingymagik/server/resolver/entities"
	"golang.org/x/net/dns/dnsmessage"
	"log"
	"net"
	"sync"
)

type Server struct {
	udpServer net.PacketConn
	cache     *recordcache.Cache
	wg        sync.WaitGroup
	shutdown  context.CancelFunc
	ctx       context.Context
}

func NewServer(address string) (*Server, error) {
	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	udpServer, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}

	return &Server{
		udpServer: udpServer,
		cache:     recordcache.NewCache(),
		ctx:       ctx,
		shutdown:  cancel,
	}, nil
}

// Start the DNS server to listen for queries.
func (s *Server) Start() {
	log.Println("Starting DNS server on", s.udpServer.LocalAddr())

	for {
		select {
		case <-s.ctx.Done():
			// If the server is shutting down, stop accepting new requests
			log.Println("Server shutting down...")
			return
		default:
			buf := make([]byte, 514)
			n, addr, err := s.udpServer.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(*net.OpError); ok && netErr.Op == "read" {
					// If the connection is closed, exit the loop
					log.Println("Error reading from UDP connection, shutting down...")
					return
				}
				log.Println("Error reading UDP packet:", err)
				continue
			}

			s.wg.Add(1)
			go s.process(addr, buf[:n])
		}
	}
}

// Gracefully close the server and all pending requests.
func (s *Server) Close() {
	// Signal shutdown and close the UDP server connection
	s.shutdown()
	// Wait for all ongoing requests to be processed
	s.wg.Wait()

	err := s.udpServer.Close()
	if err != nil {
		log.Fatal("Error closing UDP server:", err)
	}
	log.Println("Server shut down gracefully")
}

// Process a single DNS query request.
func (s *Server) process(addr net.Addr, buf []byte) {
	defer s.wg.Done()
	rcode := dnsmessage.RCodeSuccess
	// Parse incoming DNS query
	msg, err := resolver.PacketParser(buf)
	if err != nil {
		log.Printf("Packet parsing error from %s: %v", addr, err)
		rcode = dnsmessage.RCodeFormatError
	}

	opcode := msg.Header.OpCode
	rd := msg.Header.RecursionDesired

	var records []entities.Record
	if rcode == dnsmessage.RCodeSuccess {
		for _, q := range msg.Questions {
			if q.Type == dnsmessage.TypeA {
				nips, err := resolver.ResolveDN(q.Name, msg.Header.ID, dnsmessage.TypeA, s.cache)
				if err != nil {
					log.Printf("Resolution error from %s for %s: %v", addr, q.Name, err)

					continue
				}

				if len(nips) == 0 {
					log.Printf("No IP found for %s from %s", q.Name.String(), addr)
					continue
				}

				records = append(records, nips...)
			}
		}
	}

	// Prepare the response message
	response := s.buildReplyMessage(msg.Header.ID, opcode, rd, rcode, msg.Questions, records)
	// Pack the response
	packed, err := response.Pack()
	if err != nil {
		log.Printf("Response packing error for %s: %v", addr, err)
		return
	}

	// Send the response back to the client
	err = s.reply(addr, packed)
	if err != nil {
		log.Printf("Error replying to %s: %v", addr, err)
	}
}

func (s *Server) reply(addr net.Addr, buf []byte) error {
	_, err := s.udpServer.WriteTo(buf, addr)
	return err
}

func (s *Server) buildReplyMessage(id uint16, opcode dnsmessage.OpCode, rd bool, rcode dnsmessage.RCode, questions []dnsmessage.Question, records []entities.Record) dnsmessage.Message {
	var answers []dnsmessage.Resource
	if records != nil {
		// Build DNS answer section

		for _, record := range records {
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
	}

	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 id,
			Response:           true,
			OpCode:             opcode,
			Authoritative:      false, // this server is not supported as an authoritative server
			RecursionDesired:   rd,
			RecursionAvailable: true, // If it supports recursion (RA flag is set), it will perform the necessary queries to resolve www.example.com and return the final IP address to the client - NO OTHER MODE CURRENTLY SUPPORTED
			RCode:              rcode,
		},
		Questions: questions,
		Answers:   answers,
	}

	return response
}
