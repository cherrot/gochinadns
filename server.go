package gochinadns

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// Server represents a DNS Server instance
type Server struct {
	*serverOptions
	*Client
	UDPServer *dns.Server
	TCPServer *dns.Server
}

// NewServer creates a new server instance
func NewServer(cli *Client, opts ...ServerOption) (s *Server, err error) {
	var (
		retryOpts []ServerOption
		o         = newServerOptions()
	)
	for _, f := range opts {
		if err = f(o); err != nil {
			if errors.Is(err, ErrNotReady) {
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
		Client:        cli,
		UDPServer:     &dns.Server{Addr: o.Listen, Net: "udp", ReusePort: o.ReusePort},
		TCPServer:     &dns.Server{Addr: o.Listen, Net: "tcp", ReusePort: o.ReusePort},
	}
	s.UDPServer.Handler = dns.HandlerFunc(s.Serve)
	s.TCPServer.Handler = dns.HandlerFunc(s.Serve)

	s.refineResolvers()
	return
}

// Run start the default DNS server.
func (s *Server) Run() error {
	logrus.Info("Start server at ", s.Listen)
	eg, _ := errgroup.WithContext(context.Background())
	eg.Go(s.UDPServer.ListenAndServe)
	eg.Go(s.TCPServer.ListenAndServe)
	return eg.Wait()
}

const _loop = 2

func (s *Server) refineResolvers() {
	type test struct {
		server Resolver
		errCnt int
		rttAvg time.Duration
	}

	trusted := make([]test, len(s.TrustedServers))
	untrusted := make([]test, len(s.UntrustedServers))
	tLen, uLen := len(s.TrustedServers), len(s.UntrustedServers)
	req := new(dns.Msg)

	for i, resolver := range s.TrustedServers {
		trusted[i].server = resolver
		for j := 0; j < _loop; j++ {
			for _, name := range s.TestDomains {
				req.SetQuestion(dns.Fqdn(name), dns.TypeA)
				var (
					rtt time.Duration
					err error
				)
				_, rtt, err = s.Lookup(req, resolver)
				if err != nil {
					trusted[i].errCnt++
					continue
				}
				trusted[i].rttAvg += rtt
			}
		}
		if trusted[i].rttAvg > 0 {
			trusted[i].rttAvg /= time.Duration(_loop*len(s.TestDomains) - trusted[i].errCnt)
		}
		if trusted[i].errCnt > _loop*len(s.TestDomains)/2 {
			tLen--
		}
		logrus.Infof("%s: average RTT %s with %d errors.", resolver, trusted[i].rttAvg, trusted[i].errCnt)
	}

	sort.Slice(trusted, func(i, j int) bool {
		if trusted[i].errCnt == trusted[j].errCnt {
			return trusted[i].rttAvg < trusted[j].rttAvg
		}
		return trusted[i].errCnt < trusted[j].errCnt
	})

	for i, resolver := range s.UntrustedServers {
		untrusted[i].server = resolver
		for j := 0; j < _loop; j++ {
			for _, name := range s.TestDomains {
				req.SetQuestion(dns.Fqdn(name), dns.TypeA)
				_, rtt, err := s.Lookup(req, resolver)
				if err != nil {
					untrusted[i].errCnt++
					continue
				}
				untrusted[i].rttAvg += rtt
			}
		}
		if untrusted[i].rttAvg > 0 {
			untrusted[i].rttAvg /= time.Duration(_loop*len(s.TestDomains) - untrusted[i].errCnt)
		}
		if untrusted[i].errCnt > _loop*len(s.TestDomains)/2 {
			uLen--
		}
		logrus.Infof("%s: average RTT %s with %d errors.", resolver, untrusted[i].rttAvg, untrusted[i].errCnt)
	}

	sort.Slice(untrusted, func(i, j int) bool {
		if untrusted[i].errCnt == untrusted[j].errCnt {
			return untrusted[i].rttAvg < untrusted[j].rttAvg
		}
		return untrusted[i].errCnt < untrusted[j].errCnt
	})

	s.TrustedServers = make([]Resolver, len(trusted))
	s.UntrustedServers = make([]Resolver, len(untrusted))
	for i, t := range trusted {
		s.TrustedServers[i] = t.server
	}
	for i, t := range untrusted {
		s.UntrustedServers[i] = t.server
	}

	if tLen == 0 {
		logrus.Error("There seems to be no available trusted resolver. Server may not behave properly.")
	}
	if uLen == 0 && s.Bidirectional {
		logrus.Error("There seems to be no untrusted resolver. Server may not behave properly in bidirectional mode.")
	}

	logrus.Info("Refined trusted resolvers: ", s.TrustedServers)
	logrus.Info("Refined untrusted resolvers: ", s.UntrustedServers)
}
