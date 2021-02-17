/*
	Package main (lookup command) implements a DNS lookup tool (like `dig`) for testing.
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	flag.Parse()
	args := flag.Args()
	question, resolver := parseArgs(args)

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(question), dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, resolver)

	if r == nil {
		log.Fatalf("*** error: %s\n", err.Error())
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Fatalf(" *** invalid answer name %s after MX query for %s\n", os.Args[1], os.Args[1])
	}

	// Stuff must be in the answer section
	for _, a := range r.Answer {
		fmt.Printf("%v\n", a)
	}
}

func parseArgs(args []string) (question, resolver string) {
	for _, e := range args {
		if len(e) > 1 && e[0] == '@' {
			resolver := e[1:]
			if _, _, err := net.SplitHostPort(resolver); err != nil {
				if strings.Contains(err.Error(), "missing port") {
					resolver = net.JoinHostPort(resolver, "53")
				}
			}
		} else {
			question = e
		}
	}
	if resolver == "" {
		config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
		resolver = net.JoinHostPort(config.Servers[0], config.Port)
	}
	return
}
