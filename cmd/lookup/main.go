/*
	Package main (lookup command) implements a DNS lookup tool (like `dig`) for testing.
*/
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cherrot/gochinadns"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

var (
	flagUDPMaxBytes = flag.Int("udp-max-bytes", 4096, "Default DNS max message size on UDP.")
	flagMutation    = flag.Bool("m", false, "Enable compression pointer mutation in DNS queries.")
	flagTimeout     = flag.Duration("timeout", 2*time.Second, "DNS request timeout")
	flagVerbose     = flag.Bool("v", false, "Enable verbose logging.")
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] [proto[+proto]]@server www.domain.com\n", os.Args[0])
	// TODO: supported schemas
	fmt.Fprintln(flag.CommandLine.Output(), "Where proto being one of: udp, tcp.")
	fmt.Fprintln(flag.CommandLine.Output(), "\nOptions:")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if *flagVerbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
	args := flag.Args()
	question, resolver := parseArgs(args)

	copts := []gochinadns.ClientOption{
		gochinadns.WithUDPMaxBytes(*flagUDPMaxBytes),
		gochinadns.WithMutation(*flagMutation),
		gochinadns.WithTimeout(*flagTimeout),
	}

	client := gochinadns.NewClient(copts...)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(question), dns.TypeA)
	m.RecursionDesired = true

	r, rtt, err := client.Lookup(m, resolver)

	if r == nil {
		logrus.Fatalln(err)
	}

	fmt.Println(r)
	fmt.Println(";; Query time:", rtt)
	fmt.Println(";; SERVER:", resolver.Addr)
}

func parseArgs(args []string) (question string, resolver gochinadns.Resolver) {
	for _, arg := range args {
		if strings.Contains(arg, "@") {
			if arg[0] == '@' {
				arg = arg[1:]
			}
			var err error
			if resolver, err = gochinadns.ParseResolver(arg, false); err != nil {
				logrus.Fatalln(err)
			}
		} else {
			question = arg
		}
	}
	if resolver.Addr == "" {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			logrus.Fatalln(err)
		}
		resolver = gochinadns.Resolver{
			Addr:      net.JoinHostPort(config.Servers[0], config.Port),
			Protocols: []string{"udp", "tcp"},
		}
	}
	return
}
