package main

import (
	"context"
	"flag"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var udpCli = &dns.Client{SingleInflight: true}
var tcpCli = &dns.Client{SingleInflight: true, Net: "tcp"}

var (
	flagListen      = flag.String("listen", "[::]:5553", "Listening address")
	flagUDPMaxBytes = flag.Int("udpMaxBytes", 1410, "Default DNS max message size on UDP.")
)

// DNS Proxy Implementation Guidelines: https://tools.ietf.org/html/rfc5625
// DNS query processing: https://tools.ietf.org/html/rfc1034#section-3.7
// Happy Eyeballs: https://tools.ietf.org/html/rfc6555#section-5.4 and #section-6
func handle(w dns.ResponseWriter, req *dns.Msg) {
	// defer w.Close()
	logrus.Infoln("Question:", &req.Question[0])

	req.RecursionDesired = true
	// https://tools.ietf.org/html/rfc6891#section-6.2.5
	if e := req.IsEdns0(); e != nil {
		if e.UDPSize() < uint16(*flagUDPMaxBytes) {
			e.SetUDPSize(uint16(*flagUDPMaxBytes))
		}
	} else {
		req.SetEdns0(uint16(*flagUDPMaxBytes), false)
	}

	reply, rtt, err := udpCli.Exchange(req, "119.29.29.29:53")
	if err != nil {
		logrus.WithError(err).Error("UDP query failed.")
		reply, rtt, err = tcpCli.Exchange(req, "119.29.29.29:53")
		if err != nil {
			logrus.WithError(err).Error("TCP query failed.")
		}
	}
	if reply != nil {
		logrus.Infof("Query RTT: %s", rtt)
		// https://github.com/miekg/dns/issues/216
		reply.Compress = true
	} else {
		reply = new(dns.Msg)
		reply.SetReply(req)
	}

	w.WriteMsg(reply)
}

func main() {
	flag.Parse()
	dns.HandleFunc(".", handle)
	udpServer := &dns.Server{Addr: *flagListen, Net: "udp", ReusePort: true}
	tcpServer := &dns.Server{Addr: *flagListen, Net: "tcp", ReusePort: true}

	eg, _ := errgroup.WithContext(context.Background())
	eg.Go(udpServer.ListenAndServe)
	eg.Go(tcpServer.ListenAndServe)
	eg.Wait()
}
