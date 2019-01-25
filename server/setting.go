package server

import (
	"flag"
	"net"
	"strconv"
	"strings"
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
	flagCHNList         = flag.String("c", "./chnroute.txt", "Path to China route list. See http://ipverse.net")
	flagIPBlacklist     = flag.String("l", "", "Path to IP blacklist file.")
	flagDomainBlacklist = flag.String("domain-blacklist", "", "Path to domain blacklist file.")
	flagDomainOverseas  = flag.String("domain-overseas", "", "Path to overseas domains list. Queries of these domains would not be sent to DNS servers in China.")

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

type resolver struct {
	Addr            string
	PointerMutation bool
}

// Setting maintains server settings and status.
type Setting struct {
	Listen         string
	TrustedServers map[string]resolver
}

func loadSettings() error {
	// normalize flagListen
	if *flagListen == defaultListen {
		host, port, _ := net.SplitHostPort(defaultListen)
		iport, _ := strconv.Atoi(port)
		if *flagBind != host || *flagPort != iport {
			*flagListen = net.JoinHostPort(host, port)
		}
	}
	return nil
}
