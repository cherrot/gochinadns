package gochinadns

import (
	"context"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// Server represents a DNS Server instance
type Server struct {
	*serverOptions
	UDPCli *dns.Client
	TCPCli *dns.Client
}

// NewServer creates a new server instance
func NewServer(opts ...ServerOption) (s *Server, err error) {
	var (
		retryOpts []ServerOption
		o         = newServerOptions()
	)
	for _, f := range opts {
		if err = f(o); err != nil {
			if err == errNotReady {
				retryOpts = append(retryOpts, f)
				continue
			}
			return
		}
	}

	o.normalizeChinaCIDR()

	for _, f := range retryOpts {
		if err = f(o); err != nil {
			return
		}
	}

	err = nil
	s = &Server{
		serverOptions: o,
		UDPCli:        &dns.Client{Timeout: s.Timeout, Net: "udp"},
		TCPCli:        &dns.Client{Timeout: s.Timeout, Net: "tcp"},
	}

	if err = s.checkDNSConnection(); err != nil {
		return nil, err
	}
	return
}

// Run start the default DNS server.
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

// TODO: check resovers (drop from trusted servers which is not mutation capable)
// If there is no valid server, an error will return.
func (s *Server) checkDNSConnection() error {
	for _, resolver := range s.ogTrustedServers {
	}
}
