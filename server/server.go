package server

import (
	"context"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// Server represents an instance of this DNS Server
type Server struct {
	Setting
}

// New initialize a new *Server instance
func New() (*Server, error) {
	return new(Server), nil
}

// Run starts DNS server.
func (s *Server) Run() error {
	if *flagMutation {
		dns.HandleFunc(".", handleMutation)
	} else {
		dns.HandleFunc(".", handle)
	}
	udpServer := &dns.Server{Addr: *flagListen, Net: "udp", ReusePort: true}
	tcpServer := &dns.Server{Addr: *flagListen, Net: "tcp", ReusePort: true}

	eg, _ := errgroup.WithContext(context.Background())
	eg.Go(udpServer.ListenAndServe)
	eg.Go(tcpServer.ListenAndServe)
	return eg.Wait()
}
