package server

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/yl2chen/cidranger"
)

const defaultListen = "[::]:53"

var (
	flagListen          = flag.String("listen", defaultListen, "Listening address. This will override -b and -p params.")
	flagBind            = flag.String("b", "::", "Bind address.")
	flagPort            = flag.Int("p", 53, "Listening port.")
	flagUDPMaxBytes     = flag.Int("udp-max-bytes", 1410, "Default DNS max message size on UDP.")
	flagForceTCP        = flag.Bool("force-tcp", false, "Force DNS queries use TCP only.")
	flagMutation        = flag.Bool("m", true, "Enable compression pointer mutation in DNS queries.")
	flagBidirectional   = flag.Bool("d", true, "Enable bi-directional CHNRoute filter.")
	flagDelay           = flag.Float64("y", 0.3, "Delay time for suspects. This param has no effect, only for backward compatibility.")
	flagCHNList         = flag.String("c", "./chnroute.txt", "Path to China route list. Both IPv4 and IPv6 are supported. See http://ipverse.net")
	flagIPBlacklist     = flag.String("l", "", "Path to IP blacklist file.")
	flagDomainBlacklist = flag.String("domain-blacklist", "", "Path to domain blacklist file.")
	flagDomainPolluted  = flag.String("domain-polluted", "", "Path to polluted domains list. Queries of these domains will not be sent to DNS in China.")

	flagResolvers        resolverAddrs = []string{"119.29.29.29:53", "114.114.114.114:53", "8.8.8.8:53", "208.67.222.222:443"}
	flagTrustedResolvers resolverAddrs
)

func init() {
	flag.Var(&flagResolvers, "s", "Upstream DNS servers to use.")
	flag.Var(&flagTrustedResolvers, "trusted-servers", "Servers lie in China but the answer of whom can be trusted.")
}

type resolverAddrs []string

func (rs *resolverAddrs) String() string {
	sb := new(strings.Builder)

	lastIdx := len(*rs) - 1
	for i, addr := range *rs {
		if host, port, _ := net.SplitHostPort(addr); port == "53" {
			sb.WriteString(host)
		} else {
			sb.WriteString(addr)
		}
		if i < lastIdx {
			sb.WriteByte(',')
		}
	}
	return sb.String()
}

func (rs *resolverAddrs) Set(s string) error {
	addrs := strings.Split(s, ",")
	for i, addr := range addrs {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			if strings.Contains(err.Error(), "missing port") {
				addrs[i] = net.JoinHostPort(addr, "53")
			} else {
				return err
			}
		}
	}
	*rs = addrs
	return nil
}

// Resolver represents a DNS resolver.
type Resolver struct {
	Addr            string
	PointerMutation bool
}

// Setting maintains server settings and status.
type Setting struct {
	Listen           string
	ChinaCIDR        cidranger.Ranger
	TrustedServers   map[string]*Resolver // addr -> resolver
	UntrustedServers map[string]*Resolver
}

// GenServerSetting generates server setting.
func GenServerSetting() (*Setting, error) {
	s := new(Setting)
	return s, breakWhenError(
		s.parseListen,
		s.parseCHNList,
		s.parseResolvers,
		s.validateResolvers,
	)
}

func (s *Setting) parseListen() error {
	// normalize listening address
	s.Listen = *flagListen
	if *flagListen == defaultListen {
		host, port, _ := net.SplitHostPort(defaultListen)
		iport, _ := strconv.Atoi(port)
		if *flagBind != host || *flagPort != iport {
			s.Listen = net.JoinHostPort(host, port)
		}
	}
	return nil
}

func (s *Setting) parseCHNList() error {
	s.ChinaCIDR = cidranger.NewPCTrieRanger()
	if *flagCHNList != "" {
		file, err := os.Open(*flagCHNList)
		if err != nil {
			return err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			_, network, err := net.ParseCIDR(scanner.Text())
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("parse %s as CIDR failed", scanner.Text()))
			}
			s.ChinaCIDR.Insert(cidranger.NewBasicRangerEntry(*network))
		}
		if err := scanner.Err(); err != nil {
			return errors.Wrap(err, "fail to scan china route list file")
		}
	}
	return nil
}

func (s *Setting) parseResolvers() error {
	s.TrustedServers, s.UntrustedServers = make(map[string]*Resolver), make(map[string]*Resolver)
	for _, addr := range flagTrustedResolvers {
		s.TrustedServers[addr] = &Resolver{Addr: addr, PointerMutation: *flagMutation}
	}
	for _, addr := range flagResolvers {
		host, _, _ := net.SplitHostPort(addr)
		contain, err := s.ChinaCIDR.Contains(net.ParseIP(host))
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("fail to check whether %s is in China", host))
		}
		if contain {
			s.UntrustedServers[addr] = &Resolver{Addr: addr}
		} else {
			s.TrustedServers[addr] = &Resolver{Addr: addr, PointerMutation: *flagMutation}
		}
	}
	return nil
}

// TODO: check resovers (drop from trusted servers which is not mutation capable)
func (s *Setting) validateResolvers() error {
	return nil
}

func breakWhenError(funcs ...func() error) (err error) {
	for _, f := range funcs {
		if err = f(); err != nil {
			return
		}
	}
	return
}
