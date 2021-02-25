package gochinadns

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/yl2chen/cidranger"
)

var (
	ErrEmptyPath = errors.New("empty path")
)

// ServerOption provides ChinaDNS server options. Please use WithXXX functions to generate Options.
type ServerOption func(*serverOptions) error

type serverOptions struct {
	Listen           string           // Listening address, such as `[::]:53`, `0.0.0.0:53`
	ChinaCIDR        cidranger.Ranger // CIDR ranger to check whether an IP belongs to China
	IPBlacklist      cidranger.Ranger
	DomainBlacklist  *domainTrie
	DomainPolluted   *domainTrie
	Servers          resolverList  // DNS servers, will be partitioned into TrustedServers and UntrustedServers in bootstrap.
	TrustedServers   resolverList  // DNS servers which can be trusted
	UntrustedServers resolverList  // DNS servers which may return polluted results
	Bidirectional    bool          // Drop results of trusted servers which containing IPs in China
	ReusePort        bool          // Enable SO_REUSEPORT
	Delay            time.Duration // Delay (in seconds) to query another DNS server when no reply received
	TestDomains      []string      // Domain names to test connection health before starting a server
	SkipRefine       bool
}

func newServerOptions() *serverOptions {
	return &serverOptions{
		Listen:      "[::]:53",
		TestDomains: []string{"qq.com"},
		ChinaCIDR:   cidranger.NewPCTrieRanger(),
		IPBlacklist: cidranger.NewPCTrieRanger(),
	}
}

func WithListenAddr(addr string) ServerOption {
	return func(o *serverOptions) error {
		o.Listen = addr
		return nil
	}
}

func WithCHNList(path string) ServerOption {
	return func(o *serverOptions) error {
		if path == "" {
			return fmt.Errorf("%w for China route list", ErrEmptyPath)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("fail to open China route list: %w", err)

		}
		defer file.Close()

		if o.ChinaCIDR == nil {
			o.ChinaCIDR = cidranger.NewPCTrieRanger()
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			_, network, err := net.ParseCIDR(scanner.Text())
			if err != nil {
				return fmt.Errorf("parse %s as CIDR failed: %v", scanner.Text(), err.Error())
			}
			err = o.ChinaCIDR.Insert(cidranger.NewBasicRangerEntry(*network))
			if err != nil {
				return fmt.Errorf("insert %s as CIDR failed: %v", scanner.Text(), err.Error())
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("fail to scan china route list: %v", err.Error())
		}
		return nil
	}
}

func WithIPBlacklist(path string) ServerOption {
	return func(o *serverOptions) error {
		if path == "" {
			return fmt.Errorf("%w for IP blacklist", ErrEmptyPath)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("fail to open IP blacklist: %w", err)
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
					return fmt.Errorf("parse %s as CIDR failed: %v", scanner.Text(), err.Error())
				}
				l := 8 * len(ip)
				network = &net.IPNet{IP: ip, Mask: net.CIDRMask(l, l)}
			}
			err = o.IPBlacklist.Insert(cidranger.NewBasicRangerEntry(*network))
			if err != nil {
				return fmt.Errorf("insert %s as CIDR failed: %v", scanner.Text(), err.Error())
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("fail to scan IP blacklist: %v", err.Error())
		}
		return nil
	}
}

func WithDomainBlacklist(path string) ServerOption {
	return func(o *serverOptions) error {
		if path == "" {
			return fmt.Errorf("%w for domain blacklist", ErrEmptyPath)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("fail to open domain blacklist: %w", err)
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
			return fmt.Errorf("fail to scan domain blacklist: %v", err.Error())
		}
		return nil
	}
}

func WithDomainPolluted(path string) ServerOption {
	return func(o *serverOptions) error {
		if path == "" {
			return fmt.Errorf("%w for polluted domain list", ErrEmptyPath)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("fail to open polluted domain list: %w", err)
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
			return fmt.Errorf("fail to scan polluted domain list: %v", err.Error())
		}
		return nil
	}
}

func WithTrustedResolvers(tcpOnly bool, resolvers ...string) ServerOption {
	return func(o *serverOptions) error {
		for _, schema := range resolvers {
			newResolver, err := ParseResolver(schema, tcpOnly)
			if err != nil {
				return err
			}
			o.TrustedServers = uniqueAppendResolver(o.TrustedServers, newResolver)
		}
		return nil
	}
}

func WithResolvers(tcpOnly bool, resolvers ...string) ServerOption {
	return func(o *serverOptions) error {
		for _, schema := range resolvers {
			newResolver, err := ParseResolver(schema, tcpOnly)
			if err != nil {
				return err
			}
			o.Servers = uniqueAppendResolver(o.Servers, newResolver)
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

func uniqueAppendResolver(to []*Resolver, item *Resolver) []*Resolver {
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

func WithSkipRefineResolvers(skip bool) ServerOption {
	return func(o *serverOptions) error {
		o.SkipRefine = skip
		return nil
	}
}
