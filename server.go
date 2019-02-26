package gochinadns

import (
	"context"
	"sort"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// Server represents a DNS Server instance
type Server struct {
	*serverOptions
	UDPCli    *dns.Client
	TCPCli    *dns.Client
	UDPServer *dns.Server
	TCPServer *dns.Server
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
		UDPCli:        &dns.Client{Timeout: o.Timeout, Net: "udp"},
		TCPCli:        &dns.Client{Timeout: o.Timeout, Net: "tcp"},
		UDPServer:     &dns.Server{Addr: o.Listen, Net: "udp", ReusePort: o.ReusePort},
		TCPServer:     &dns.Server{Addr: o.Listen, Net: "tcp", ReusePort: o.ReusePort},
	}
	s.UDPServer.Handler = dns.HandlerFunc(s.Serve)
	s.TCPServer.Handler = dns.HandlerFunc(s.Serve)

	if err = s.checkDNSConnection(); err != nil {
		return nil, err
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

const _loop = 5

func (s *Server) checkDNSConnection() error {
	type test struct {
		addr   string
		errCnt int
		rttAvg time.Duration
	}

	trusted := make([]test, len(s.TrustedServers))
	untrusted := make([]test, len(s.UntrustedServers))
	tLen, uLen := len(s.TrustedServers), len(s.UntrustedServers)
	req := new(dns.Msg)

	for i, resolver := range s.TrustedServers {
		trusted[i].addr = resolver
		for j := 0; j < _loop; j++ {
			for _, name := range s.TestDomains {
				req.SetQuestion(dns.Fqdn(name), dns.TypeA)
				var (
					rtt time.Duration
					err error
				)
				if s.Mutation {
					_, rtt, err = s.LookupMutation(req, resolver)
				} else {
					_, rtt, err = s.Lookup(req, resolver)
				}
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
		if trusted[i].errCnt > 2*len(s.TestDomains) {
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
	trusted = trusted[:tLen]

	for i, resolver := range s.UntrustedServers {
		untrusted[i].addr = resolver
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
		if untrusted[i].errCnt > 2*len(s.TestDomains) {
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
	untrusted = untrusted[:uLen]

	s.TrustedServers = make([]string, len(trusted))
	s.UntrustedServers = make([]string, len(untrusted))
	for i, t := range trusted {
		s.TrustedServers[i] = t.addr
	}
	for i, t := range untrusted {
		s.UntrustedServers[i] = t.addr
	}

	if len(s.TrustedServers) == 0 {
		return errors.New("server cannot work with no trusted resolvers")
	}
	if len(s.UntrustedServers) == 0 && s.Bidirectional {
		return errors.New("untrusted resolvers cannot be empty in bidirectional mode")
	}

	logrus.Info("Refined trusted resolvers: ", s.TrustedServers)
	logrus.Info("Refined untrusted resolvers: ", s.UntrustedServers)
	return nil
}
