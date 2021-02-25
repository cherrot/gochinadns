package main

import (
	"flag"
	"net"
	"strings"
	"time"
)

var (
	flagVersion = flag.Bool("V", false, "Print version and exit.")
	flagVerbose = flag.Bool("v", false, "Enable verbose logging.")

	flagBind            = flag.String("b", "::", "Bind address.")
	flagPort            = flag.Int("p", 53, "Listening port.")
	flagUDPMaxBytes     = flag.Int("udp-max-bytes", 4096, "Default DNS max message size on UDP.")
	flagForceTCP        = flag.Bool("force-tcp", false, "Force DNS queries use TCP only. Only applies to resolvers declared in ip:port format.")
	flagMutation        = flag.Bool("m", false, "Enable compression pointer mutation in DNS queries.")
	flagBidirectional   = flag.Bool("d", true, "Drop results of trusted servers which containing IPs in China. (Bidirectional mode.)")
	flagReusePort       = flag.Bool("reuse-port", true, "Enable SO_REUSEPORT to gain some performance optimization. Need Linux>=3.9")
	flagTimeout         = flag.Duration("timeout", time.Second, "DNS request timeout")
	flagDelay           = flag.Float64("y", 0.1, "Delay (in seconds) to query another DNS server when no reply received.")
	flagTestDomains     = flag.String("test-domains", "www.qq.com", "Domain names to test DNS connection health, separated by comma.")
	flagCHNList         = flag.String("c", "./china.list", "Path to China route list. Both IPv4 and IPv6 are supported. See http://ipverse.net")
	flagIPBlacklist     = flag.String("l", "", "Path to IP blacklist file.")
	flagDomainBlacklist = flag.String("domain-blacklist", "", "Path to domain blacklist file.")
	flagDomainPolluted  = flag.String("domain-polluted", "", "Path to polluted domains list. Queries of these domains will not be sent to DNS in China.")
	flagSkipRefine      = flag.Bool("skip-refine", false, "If true, will keep the specified resolver order and skip the refine process.")

	flagResolvers        resolverAddrs = []string{"udp+tcp@119.29.29.29:53", "udp+tcp@114.114.114.114:53"}
	flagTrustedResolvers resolverAddrs = []string{}
)

func init() {
	flag.Var(&flagResolvers, "s", "Comma separated list of upstream DNS servers. Need China route list to check whether it's a trusted server or not.\n"+
		"Servers can be in format ip:port or protocol[+protocol]@ip:port where protocol is udp or tcp.\n"+
		"Protocols are dialed in order left to right. Rightmost protocol will only be dialed if the leftmost fails.\n"+
		"Protocols will override force-tcp flag. "+
		"If empty, protocol defaults to udp+tcp (tcp if force-tcp is set) and port defaults to 53.\n"+
		"Examples: udp@8.8.8.8,udp+tcp@127.0.0.1:5353,1.1.1.1")
	flag.Var(&flagTrustedResolvers, "trusted-servers", "Comma separated list of servers which (located in China but) can be trusted. \n"+
		"Uses the same format as -s.")
}

type resolverAddrs []string

func (rs *resolverAddrs) String() string {
	sb := new(strings.Builder)

	lastIdx := len(*rs) - 1
	for i, addr := range *rs {
		if host, port, err := net.SplitHostPort(addr); err != nil {
			sb.WriteString(addr)
		} else if port == "53" {
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
	*rs = addrs
	return nil
}
