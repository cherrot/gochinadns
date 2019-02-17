package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cherrot/gochinadns"
)

const (
	defaultListen = "[::]:53"
)

var (
	flagVersion = flag.Bool("V", false, "Print version and exit.")
	flagVerbose = flag.Bool("v", false, "Enable verbose logging.")

	flagListen          = flag.String("listen", defaultListen, "Listening address. This will override -b and -p params.")
	flagBind            = flag.String("b", "::", "Bind address.")
	flagPort            = flag.Int("p", 53, "Listening port.")
	flagUDPMaxBytes     = flag.Int("udp-max-bytes", 1410, "Default DNS max message size on UDP.")
	flagForceTCP        = flag.Bool("force-tcp", false, "Force DNS queries use TCP only.")
	flagMutation        = flag.Bool("m", true, "Enable compression pointer mutation in DNS queries.")
	flagBidirectional   = flag.Bool("d", true, "Drop results of trusted servers which containing IPs in China.")
	flagTimeout         = flag.Duration("timeout", time.Second, "DNS request timeout")
	flagDelay           = flag.Float64("y", 0.1, "Delay (in seconds) to query another DNS server when no reply received.")
	flagTestDomains     = flag.String("test-domains", "qq.com,163.com", "Domain names to test DNS connection health.")
	flagCHNList         = flag.String("c", "./chnroute.txt", "Path to China route list. Both IPv4 and IPv6 are supported. See http://ipverse.net")
	flagIPBlacklist     = flag.String("l", "", "Path to IP blacklist file.")
	flagDomainBlacklist = flag.String("domain-blacklist", "", "Path to domain blacklist file.")
	flagDomainPolluted  = flag.String("domain-polluted", "", "Path to polluted domains list. Queries of these domains will not be sent to DNS in China.")

	flagResolvers        resolverAddrs = []string{"119.29.29.29:53", "114.114.114.114:53", "8.8.8.8:53", "208.67.222.222:443"}
	flagTrustedResolvers resolverAddrs
)

func init() {
	flag.Var(&flagResolvers, "s", "Upstream DNS servers. Need China route list to check whether it's a trusted server or not.")
	flag.Var(&flagTrustedResolvers, "trusted-servers", "Servers which (located in China but) can be trusted.")
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

func parseListenAddr() string {
	listen := *flagListen
	if *flagListen == defaultListen {
		host, port, _ := net.SplitHostPort(defaultListen)
		iport, _ := strconv.Atoi(port)
		if *flagBind != host || *flagPort != iport {
			listen = net.JoinHostPort(host, port)
		}
	}
	return listen
}

func main() {
	flag.Parse()
	if *flagVersion {
		fmt.Println(gochinadns.GetVersion())
		return
	}
	if *flagVerbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	listen := parseListenAddr()
	opts := []gochinadns.ServerOption{
		gochinadns.WithListenAddr(listen),
		gochinadns.WithUDPMaxBytes(*flagUDPMaxBytes),
		gochinadns.WithTCPOnly(*flagForceTCP),
		gochinadns.WithMutation(*flagMutation),
		gochinadns.WithBidirectional(*flagBidirectional),
		gochinadns.WithTimeout(*flagTimeout),
		gochinadns.WithDelay(time.Duration(*flagDelay * float64(time.Second))),
		gochinadns.WithTrustedResolvers(flagTrustedResolvers...),
		gochinadns.WithResolvers(flagResolvers...),
	}
	if *flagTestDomains != "" {
		opts = append(opts, gochinadns.WithTestDomains(strings.Split(*flagTestDomains, ",")...))
	}
	if *flagCHNList != "" {
		opts = append(opts, gochinadns.WithCHNList(*flagCHNList))
	}
	if *flagIPBlacklist != "" {
		opts = append(opts, gochinadns.WithIPBlacklist(*flagIPBlacklist))
	}
	if *flagDomainBlacklist != "" {
		opts = append(opts, gochinadns.WithDomainBlacklist(*flagDomainBlacklist))
	}
	if *flagDomainPolluted != "" {
		opts = append(opts, gochinadns.WithDomainPolluted(*flagDomainPolluted))
	}

	server, err := gochinadns.NewServer(opts...)
	if err != nil {
		panic(err)
	}
	panic(server.Run())
}
