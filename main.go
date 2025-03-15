package main

import (
	"dnsthingymagik/server"
	"log"
)

func main() {
	s, err := server.NewServer(":53")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	s.Start()
}
