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

	if !s.SkipRefine {
		s.refineResolvers()
	}
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

func (s *Server) refineResolvers() {
	type test struct {
		server *Resolver
		errCnt int
		rttAvg time.Duration
	}

	refine := func(resolvers resolverList) (availLen int) {
		const _loop = 3
		availLen = len(resolvers)
		var (
			tests = make([]test, availLen)
			req   = new(dns.Msg)
		)
		for i, rs := range resolvers {
			tests[i].server = rs
			for j := 0; j < _loop; j++ {
				for _, name := range s.TestDomains {
					req.SetQuestion(dns.Fqdn(name), dns.TypeA)
					_, rtt, err := s.Lookup(req, rs)
					if err != nil {
						tests[i].errCnt++
						continue
					}
					tests[i].rttAvg += rtt
				}
			}
			if tests[i].rttAvg > 0 {
				tests[i].rttAvg /= time.Duration(_loop*len(s.TestDomains) - tests[i].errCnt)
			}
			if tests[i].errCnt > _loop*len(s.TestDomains)/2 {
				availLen--
			}
			logrus.Infof("%s: average RTT %s with %d errors.", rs, tests[i].rttAvg, tests[i].errCnt)
		}

		// sort resolvers in place based on tests
		sort.Slice(resolvers, func(i, j int) bool {
			if tests[i].errCnt == tests[j].errCnt {
				return tests[i].rttAvg < tests[j].rttAvg
			}
			return tests[i].errCnt < tests[j].errCnt
		})

		return availLen
	}

	availTrusted := refine(s.TrustedServers)
	availUntrusted := refine(s.UntrustedServers)

	if availTrusted == 0 {
		logrus.Error("There seems to be no available trusted resolver. Server may not behave properly.")
	}
	if availUntrusted == 0 && s.Bidirectional {
		logrus.Error("There seems to be no untrusted resolver. Server may not behave properly in bidirectional mode.")
	}

	logrus.Info("Refined trusted resolvers: ", s.TrustedServers)
	logrus.Info("Refined untrusted resolvers: ", s.UntrustedServers)
}
