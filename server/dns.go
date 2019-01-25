package server

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var udpCli = &dns.Client{Timeout: time.Second * 2}
var tcpCli = &dns.Client{Timeout: time.Second * 2, SingleInflight: true, Net: "tcp"}

// DNS Proxy Implementation Guidelines: https://tools.ietf.org/html/rfc5625
// DNS query processing: https://tools.ietf.org/html/rfc1034#section-3.7
// Happy Eyeballs: https://tools.ietf.org/html/rfc6555#section-5.4 and #section-6
func handle(w dns.ResponseWriter, req *dns.Msg) {
	// defer w.Close()
	logrus.Debug("Question:", &req.Question[0])

	req.RecursionDesired = true
	if *flagUDPMaxBytes > dns.MinMsgSize {
		// https://tools.ietf.org/html/rfc6891#section-6.2.5
		if e := req.IsEdns0(); e != nil {
			if e.UDPSize() < uint16(*flagUDPMaxBytes) {
				e.SetUDPSize(uint16(*flagUDPMaxBytes))
			}
		} else {
			req.SetEdns0(uint16(*flagUDPMaxBytes), false)
		}
	}

	reply, rtt, err := udpCli.Exchange(req, "8.8.8.8:53")
	if err != nil {
		logrus.WithError(err).Error("UDP query failed.")
		reply, rtt, err = tcpCli.Exchange(req, "8.8.8.8:53")
		if err != nil {
			logrus.WithError(err).Error("TCP query failed.")
		}
	}
	if reply != nil {
		logrus.Debugf("Query RTT: %s", rtt)
		// https://github.com/miekg/dns/issues/216
		reply.Compress = true
	} else {
		reply = new(dns.Msg)
		reply.SetReply(req)
	}

	w.WriteMsg(reply)
}

// DNS Compression: https://tools.ietf.org/html/rfc1035#section-4.1.4
// DNS compression pointer mutation: https://gist.github.com/klzgrad/f124065c0616022b65e5#file-sendmsg-c-L30-L63
func handleMutation(w dns.ResponseWriter, req *dns.Msg) {
	// defer w.Close()
	logrus.Debug("Question:", &req.Question[0])

	req.RecursionDesired = true
	if *flagUDPMaxBytes > dns.MinMsgSize {
		// https://tools.ietf.org/html/rfc6891#section-6.2.5
		if e := req.IsEdns0(); e != nil {
			if e.UDPSize() < uint16(*flagUDPMaxBytes) {
				e.SetUDPSize(uint16(*flagUDPMaxBytes))
			}
		} else {
			req.SetEdns0(uint16(*flagUDPMaxBytes), false)
		}
	}

	reply, rtt, err := exchangeMutation(req)
	if err == nil {
		logrus.Debugf("Query RTT: %s", rtt)
		reply.Compress = true
	} else {
		logrus.WithError(err).Error("Exchange failed.")
		reply = new(dns.Msg)
		reply.SetReply(req)
	}

	w.WriteMsg(reply)
}

func exchangeMutation(req *dns.Msg) (reply *dns.Msg, rtt time.Duration, err error) {
	buffer, err := req.Pack()
	if err != nil {
		return
	}

	if len(req.Question) > 0 {
		buffer = mutateQuestion(buffer)
	}

	conn, err := udpCli.Dial("8.8.8.8:53")
	if err != nil {
		return
	}
	defer conn.Close()

	// If EDNS0 is used use that for size.
	opt := req.IsEdns0()
	if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
		conn.UDPSize = opt.UDPSize()
	}
	// Otherwise use the client's configured UDP size.
	if opt == nil && udpCli.UDPSize >= dns.MinMsgSize {
		conn.UDPSize = udpCli.UDPSize
	}

	conn.TsigSecret = udpCli.TsigSecret
	t := time.Now()
	conn.SetWriteDeadline(t.Add(udpCli.Timeout))
	if _, err = conn.Write(buffer); err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(udpCli.Timeout))
	reply, err = conn.ReadMsg()
	if err == nil && reply.Id != req.Id {
		err = dns.ErrId
	}
	rtt = time.Since(t)
	return
}

func mutateQuestion(bytes []byte) []byte {
	// 16 is the minimum length of a valid DNS query
	length := len(bytes)
	if length <= 16 {
		return bytes
	}

	var (
		buffer = bytes
		found  = false
		offset = 12
	)
	for offset < length-4 {
		if bytes[offset]&0xC0 != 0 {
			break
		}
		// end of the QName
		if bytes[offset] == 0 {
			found = true
			offset++
			break
		}
		// skip by label length
		offset += int(bytes[offset]) + 1
	}

	if found {
		buffer = make([]byte, length+1)
		copy(buffer, bytes[:offset-1])
		buffer[offset-1], buffer[offset] = 0xC0, 0x06
		copy(buffer[offset+1:], bytes[offset:])
	}
	return buffer
}

// Server represents an instance of this DNS Server
type Server struct {
	Setting
}

// New initialize a new *Server instance
func New() (*Server, error) {
	return new(Server), nil
}

// Run starts DNS server.
func (s *Server) Run() error {
	if *flagMutation {
		dns.HandleFunc(".", handleMutation)
	} else {
		dns.HandleFunc(".", handle)
	}
	udpServer := &dns.Server{Addr: *flagListen, Net: "udp", ReusePort: true}
	tcpServer := &dns.Server{Addr: *flagListen, Net: "tcp", ReusePort: true}

	eg, _ := errgroup.WithContext(context.Background())
	eg.Go(udpServer.ListenAndServe)
	eg.Go(tcpServer.ListenAndServe)
	return eg.Wait()
}
