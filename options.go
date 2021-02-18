package gochinadns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

// ServerOption provides ChinaDNS server options. Please use WithXXX functions to generate Options.
type ServerOption func(*serverOptions) error

type serverOptions struct {
	Listen           string           //Listening address, such as `[::]:53`, `0.0.0.0:53`
	ChinaCIDR        cidranger.Ranger //CIDR ranger to check whether an IP belongs to China
	IPBlacklist      cidranger.Ranger
	DomainBlacklist  *domainTrie
	DomainPolluted   *domainTrie
	TrustedServers   resolverArray //DNS servers which can be trusted
	UntrustedServers resolverArray //DNS servers which may return polluted results
	Bidirectional    bool          //Drop results of trusted servers which containing IPs in China
	ReusePort        bool          //Enable SO_REUSEPORT
	Delay            time.Duration //Delay (in seconds) to query another DNS server when no reply received
	TestDomains      []string      //Domain names to test connection health before starting a server
}

func newServerOptions() *serverOptions {
	return &serverOptions{
		Listen:      "[::]:53",
		TestDomains: []string{"qq.com"},
		IPBlacklist: cidranger.NewPCTrieRanger(),
	}
}

func (o *serverOptions) normalizeChinaCIDR() {
	if o.ChinaCIDR == nil {
		o.ChinaCIDR = cidranger.NewPCTrieRanger()
		logrus.Warn("China route list is not specified. Disable CHNRoute.")
	}
}

var errNotReady = errors.New("not ready")

func WithListenAddr(addr string) ServerOption {
	return func(o *serverOptions) error {
		o.Listen = addr
		return nil
	}
}

func WithCHNList(path string) ServerOption {
	return func(o *serverOptions) error {
		if path == "" {
			return errors.New("empty path for China route list")
		}
		file, err := os.Open(path)
		if err != nil {
			return errors.Wrap(err, "fail to open China route list")

		}
		defer file.Close()

		if o.ChinaCIDR == nil {
			o.ChinaCIDR = cidranger.NewPCTrieRanger()
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			_, network, err := net.ParseCIDR(scanner.Text())
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("parse %s as CIDR failed", scanner.Text()))
			}
			o.ChinaCIDR.Insert(cidranger.NewBasicRangerEntry(*network))
		}
		if err := scanner.Err(); err != nil {
			return errors.Wrap(err, "fail to scan china route list")
		}
		return nil
	}
}

func WithIPBlacklist(path string) ServerOption {
	return func(o *serverOptions) error {
		if path == "" {
			return errors.New("empty path for IP blacklist")
		}
		file, err := os.Open(path)
		if err != nil {
			return errors.Wrap(err, "fail to open IP blacklist")
		}
		defer file.Close()

		if o.IPBlacklist == nil {
			o.IPBlacklist = cidranger.NewPCTrieRanger()
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			_, network, err := net.ParseCIDR(scanner.Text())
			if err != nil {
				ip := net.ParseIP(scanner.Text())
				if ip == nil {
					return errors.Wrap(err, fmt.Sprintf("parse %s as CIDR failed", scanner.Text()))
				}
				l := 8 * len(ip)
				network = &net.IPNet{IP: ip, Mask: net.CIDRMask(l, l)}
			}
			o.IPBlacklist.Insert(cidranger.NewBasicRangerEntry(*network))
		}
		if err := scanner.Err(); err != nil {
			return errors.Wrap(err, "fail to scan IP blacklist")
		}
		return nil
	}
}

func WithDomainBlacklist(path string) ServerOption {
	return func(o *serverOptions) error {
		if path == "" {
			return errors.New("empty path for domain blacklist")
		}
		file, err := os.Open(path)
		if err != nil {
			return errors.Wrap(err, "fail to open domain blacklist")
		}
		defer file.Close()

		if o.DomainBlacklist == nil {
			o.DomainBlacklist = new(domainTrie)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			o.DomainBlacklist.Add(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return errors.Wrap(err, "fail to scan domain blacklist")
		}
		return nil
	}
}

func WithDomainPolluted(path string) ServerOption {
	return func(o *serverOptions) error {
		if path == "" {
			return errors.New("empty path for domain polluted")
		}
		file, err := os.Open(path)
		if err != nil {
			return errors.Wrap(err, "fail to open domain polluted")
		}
		defer file.Close()

		if o.DomainPolluted == nil {
			o.DomainPolluted = new(domainTrie)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			o.DomainPolluted.Add(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return errors.Wrap(err, "fail to scan domain polluted")
		}
		return nil
	}
}

func WithTrustedResolvers(tcpOnly bool, resolvers ...string) ServerOption {
	return func(o *serverOptions) error {
		for _, schema := range resolvers {
			newResolver, err := ParseResolver(schema, tcpOnly)
			if err != nil {
				return errors.Wrap(err, "Schema error")
			}
			o.TrustedServers = uniqueAppendResolver(o.TrustedServers, newResolver)
		}
		return nil
	}
}

func WithResolvers(tcpOnly bool, resolvers ...string) ServerOption {
	return func(o *serverOptions) error {
		if o.ChinaCIDR == nil {
			return errNotReady
		}
		for _, schema := range resolvers {
			newResolver, err := ParseResolver(schema, tcpOnly)
			if err != nil {
				return errors.Wrap(err, "Schema error")
			}
			host, _, _ := net.SplitHostPort(newResolver.GetAddr())
			contain, err := o.ChinaCIDR.Contains(net.ParseIP(host))
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("fail to check whether %s is in China", host))
			}
			if contain {
				o.UntrustedServers = uniqueAppendResolver(o.UntrustedServers, newResolver)
			} else {
				o.TrustedServers = uniqueAppendResolver(o.TrustedServers, newResolver)
			}
		}
		return nil
	}
}

func uniqueAppendString(to []string, item string) []string {
	for _, e := range to {
		if item == e {
			return to
		}
	}
	return append(to, item)
}

func uniqueAppendResolver(to []Resolver, item Resolver) []Resolver {
	for _, e := range to {
		if item.GetAddr() == e.GetAddr() {
			return to
		}
	}
	return append(to, item)
}

func WithBidirectional(b bool) ServerOption {
	return func(o *serverOptions) error {
		o.Bidirectional = b
		return nil
	}
}

func WithReusePort(b bool) ServerOption {
	return func(o *serverOptions) error {
		o.ReusePort = b
		return nil
	}
}

func WithDelay(t time.Duration) ServerOption {
	return func(o *serverOptions) error {
		o.Delay = t
		return nil
	}
}

func WithTestDomains(testDomains ...string) ServerOption {
	return func(o *serverOptions) error {
		o.TestDomains = testDomains
		return nil
	}
}
