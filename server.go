package gochinadns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"time"

	"github.com/cherrot/gochinadns/hosts"
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
	var	o         = newServerOptions()
	for _, f := range opts {
		if err = f(o); err != nil {
			return
		}
	}

	s = &Server{
		serverOptions: o,
		Client:        cli,
		UDPServer:     &dns.Server{Addr: o.Listen, Net: "udp", ReusePort: o.ReusePort},
		TCPServer:     &dns.Server{Addr: o.Listen, Net: "tcp", ReusePort: o.ReusePort},
	}
	s.UDPServer.Handler = dns.HandlerFunc(s.Serve)
	s.TCPServer.Handler = dns.HandlerFunc(s.Serve)

	if err = s.partitionResolvers(); err != nil {
		s = nil
		return
	}
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

// partitionResolvers partitions resolvers into untrusted and trusted separately
// If a DoH server is not in an IP format, and it's hostname is not in system's hosts file (e.g. /etc/hosts),
// I will treat it a trusted server by default.
func (s *Server) partitionResolvers() error {
	for _, resolver := range s.Servers {
		var (
			ip net.IP
			err error
		)
		if len(resolver.GetProtocols()) == 1 && resolver.GetProtocols()[0] == "doh" {
			if ip, err = s.resolveDoHAddr(resolver.GetAddr()); err != nil {
				return err
			}
			if ip == nil {
				logrus.Warnf("I can't find IP for [%s] in system's hosts file, trust it by default.", resolver.GetAddr())
				s.TrustedServers = uniqueAppendResolver(s.TrustedServers, resolver)
				continue
			}
		} else {
			host, _, err := net.SplitHostPort(resolver.GetAddr())
			if err != nil {
				return err
			}
			ip = net.ParseIP(host)
		}

		contain, err := s.ChinaCIDR.Contains(ip)
		if err != nil {
			return fmt.Errorf("fail to check if %s is in China: %v", resolver.GetAddr(), err.Error())
		}
		if contain {
			s.UntrustedServers = uniqueAppendResolver(s.UntrustedServers, resolver)
		} else {
			s.TrustedServers = uniqueAppendResolver(s.TrustedServers, resolver)
		}
	}
	return nil
}

func (s *Server) refineResolvers() {
	type test struct {
		server *Resolver
		errCnt int
		rttAvg time.Duration
	}

	logrus.Infoln("Start server temporarily to refine resolvers' order.")
	go s.UDPServer.ListenAndServe() //nolint:errcheck
	go s.TCPServer.ListenAndServe() //nolint:errcheck

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
	

	t := make(resolverList, len(s.TrustedServers))
	un := make(resolverList, len(s.UntrustedServers))
	copy(t, s.TrustedServers)
	copy(un, s.UntrustedServers)
	availTrusted, availUntrusted := refine(t), refine(un)

	_ = s.UDPServer.Shutdown()
	_ = s.TCPServer.Shutdown()
	s.TrustedServers, s.UntrustedServers = t, un

	if availTrusted == 0 {
		logrus.Error("All trusted resolvers test failed. Server may not behave properly.")
	}
	if availUntrusted == 0 && s.Bidirectional {
		logrus.Error("All untrusted resolvers test failed. Server may not behave properly in bidirectional mode.")
	}

	logrus.Info("Refined trusted resolvers: ", s.TrustedServers)
	logrus.Info("Refined untrusted resolvers: ", s.UntrustedServers)
}

func (s *Server) resolveDoHAddr(addr string) (net.IP, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("cannot parse url [%s]", addr)
	}

	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}

	if ip := hosts.Lookup(host); ip != nil {
		return ip, nil
	}

	// That's it. Will not lookup in upstream servers
	return nil, nil
}
