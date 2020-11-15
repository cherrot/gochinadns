package gochinadns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// LookupFunc looks up DNS request to the given server and returns DNS reply, its RTT time and an error.
type LookupFunc func(request *dns.Msg, server resolver) (reply *dns.Msg, rtt time.Duration, err error)

func lookupInServers(
	ctx context.Context, cancel context.CancelFunc, result chan<- *dns.Msg, req *dns.Msg,
	servers []resolver, waitInterval time.Duration, lookup LookupFunc,
) {
	defer cancel()
	if len(servers) == 0 {
		return
	}
	logger := logrus.WithField("question", questionString(&req.Question[0]))

	ticker := time.NewTicker(waitInterval)
	defer ticker.Stop()
	queryNext := make(chan struct{}, len(servers))
	queryNext <- struct{}{}
	var wg sync.WaitGroup

	doLookup := func(server resolver) {
		defer wg.Done()
		logger := logger.WithField("server", server.getAddr())

		reply, rtt, err := lookup(req.Copy(), server)
		if err != nil {
			queryNext <- struct{}{}
			return
		}

		select {
		case result <- reply:
			logger.Debug("Query RTT: ", rtt)
		default:
		}
		cancel()
	}

LOOP:
	for _, server := range servers {
		select {
		case <-ctx.Done():
			break LOOP
		case <-queryNext:
			wg.Add(1)
			go doLookup(server)
		case <-ticker.C:
			wg.Add(1)
			go doLookup(server)
		}
	}

	wg.Wait()
}

// Lookup send a DNS request to the specific server and get its corresponding reply.
// DNS Proxy Implementation Guidelines: https://tools.ietf.org/html/rfc5625
// DNS query processing: https://tools.ietf.org/html/rfc1034#section-3.7
// Happy Eyeballs: https://tools.ietf.org/html/rfc6555#section-5.4 and #section-6
func (s *Server) Lookup(req *dns.Msg, server resolver) (reply *dns.Msg, rtt time.Duration, err error) {
	logger := logrus.WithFields(logrus.Fields{
		"question": questionString(&req.Question[0]),
		"server":   server,
	})

	var rtt0 time.Duration

	for _, protocol := range server.getProto() {
		switch protocol {
		case "udp":
			logger.Debug("Query upstream udp")
			reply, rtt0, err = s.UDPCli.Exchange(req, server.getAddr())
			rtt += rtt0
			if err != nil {
				logger.WithError(err).Error("Fail to send UDP query.")
			} else {
				return
			}
			if reply != nil && reply.Truncated {
				logger.Error("Truncated msg received. Consider enlarge your UDP max size.")
			}
		case "tcp":
			logger.Debug("Query upstream tcp")
			reply, rtt0, err = s.TCPCli.Exchange(req, server.getAddr())
			rtt += rtt0
			if err != nil {
				logger.WithError(err).Error("Fail to send TCP query.")
			} else {
				return
			}
		default:
			logger.Errorf("No available protocols for resolver %s", server)
			return
		}
	}
	return
}

// LookupMutation does the same as Lookup, with pointer mutation for DNS query.
// DNS Compression: https://tools.ietf.org/html/rfc1035#section-4.1.4
// DNS compression pointer mutation: https://gist.github.com/klzgrad/f124065c0616022b65e5#file-sendmsg-c-L30-L63
func (s *Server) LookupMutation(req *dns.Msg, server resolver) (reply *dns.Msg, rtt time.Duration, err error) {
	logger := logrus.WithFields(logrus.Fields{
		"question": questionString(&req.Question[0]),
		"server":   server,
	})

	var buffer []byte
	buffer, err = req.Pack()
	if err != nil {
		return nil, 0, errors.Wrap(err, "fail to pack request")
	}
	buffer = mutateQuestion(buffer)

	t := time.Now()
	for _, protocol := range server.getProto() {
		switch protocol {
		case "udp":
			logger.Debug("Query upstream udp")
			ddl := t.Add(s.UDPCli.Timeout)
			udpSize := getUDPSize(req)
			reply, err = rawLookup(s.UDPCli, req.Id, buffer, server, ddl, udpSize)
			if err != nil {
				logger.WithError(err).Error("Fail to send UDP mutation query. ")
			} else {
				rtt = time.Since(t)
				return
			}
			if reply != nil && reply.Truncated {
				logger.Error("Truncated msg received. Consider enlarge your UDP max size.")
			}
		case "tcp":
			logger.Debug("Query upstream tcp")
			ddl := time.Now().Add(s.TCPCli.Timeout)
			reply, err = rawLookup(s.TCPCli, req.Id, buffer, server, ddl, 0)
			if err != nil {
				logger.WithError(err).Error("Fail to send TCP mutation query.")
			} else {
				rtt = time.Since(t)
				return
			}
		default:
			logger.Errorf("No available protocols for resolver %s", server)
			return
		}
	}
	rtt = time.Since(t)
	return
}

func rawLookup(cli *dns.Client, id uint16, req []byte, server resolver, ddl time.Time, udpSize uint16) (*dns.Msg, error) {
	conn, err := cli.Dial(server.getAddr())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.UDPSize = udpSize

	conn.SetWriteDeadline(ddl)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(ddl)
	reply, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}
	if reply.Id != id {
		err = dns.ErrId
	}
	return reply, err
}

func setUDPSize(req *dns.Msg, size uint16) uint16 {
	if size <= dns.MinMsgSize {
		return dns.MinMsgSize
	}
	// https://tools.ietf.org/html/rfc6891#section-6.2.5
	if e := req.IsEdns0(); e != nil {
		if e.UDPSize() >= size {
			return e.UDPSize()
		}
		e.SetUDPSize(size)
		return size
	}
	req.SetEdns0(size, false)
	return size
}

func getUDPSize(req *dns.Msg) uint16 {
	if e := req.IsEdns0(); e != nil && e.UDPSize() > dns.MinMsgSize {
		return e.UDPSize()
	}
	return dns.MinMsgSize
}

func cleanEdns0(req *dns.Msg) {
	for {
		if req.IsEdns0() == nil {
			break
		}
		req.Extra = req.Extra[:len(req.Extra)-1]
	}
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

func questionString(q *dns.Question) string {
	return q.Name + " " + dns.TypeToString[q.Qtype]
}
