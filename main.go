package main

import (
	"flag"
	"log"
)

func main() {
	port  := flag.Int("port", 2222, "Port to listen on")
	host  := flag.String("host", "0.0.0.0", "Address to bind")
	conns := flag.Int("max-conns", 512, "Maximum concurrent connections")
	flag.Parse()

	listenHost = *host
	listenPort = *port
	maxConns   = *conns

	if err := runServer(); err != nil {
		log.Fatal(err)
	}
}
