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
type LookupFunc func(request *dns.Msg, server string) (reply *dns.Msg, rtt time.Duration, err error)

func lookupInServers(
	ctx context.Context, cancel context.CancelFunc, result chan<- *dns.Msg, req *dns.Msg,
	servers []string, waitInterval time.Duration, lookup LookupFunc,
) {
	defer cancel()
	if len(servers) == 0 {
		return
	}
	var errChain error
	logger := logrus.WithField("question", questionString(&req.Question[0]))

	ticker := time.NewTicker(waitInterval)
	defer ticker.Stop()
	queryNext := make(chan struct{}, len(servers))
	queryNext <- struct{}{}
	var wg sync.WaitGroup

	doLookup := func(idx int, server string) {
		defer wg.Done()
		logger := logger.WithField("server", server)

		reply, rtt, err := lookup(req, server)
		if err != nil {
			errChain = errors.Wrapf(err, "%d", idx)
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
	for idx, server := range servers {
		select {
		case <-ctx.Done():
			break LOOP
		case <-queryNext:
			wg.Add(1)
			go doLookup(idx, server)
		case <-ticker.C:
			wg.Add(1)
			go doLookup(idx, server)
		}
	}

	wg.Wait()
	if errChain != nil {
		logger.WithError(errChain).Error("Error hanppens.")
	}
}

// Lookup send a DNS request to the specific server and get its corresponding reply.
// DNS Proxy Implementation Guidelines: https://tools.ietf.org/html/rfc5625
// DNS query processing: https://tools.ietf.org/html/rfc1034#section-3.7
// Happy Eyeballs: https://tools.ietf.org/html/rfc6555#section-5.4 and #section-6
func (s *Server) Lookup(req *dns.Msg, server string) (reply *dns.Msg, rtt time.Duration, err error) {
	logger := logrus.WithFields(logrus.Fields{
		"question": questionString(&req.Question[0]),
		"server":   server,
	})

	if !s.TCPOnly {
		req := req.Copy()
		setUDPSize(req, s.UDPMaxSize)
		reply, rtt, err = s.UDPCli.Exchange(req, server)
		if err != nil {
			logger.WithError(err).Error("Fail to send UDP query. Will retry in TCP.")
		}
		if reply != nil && reply.Truncated {
			logger.Error("Truncated msg received. Will retry in TCP. Consider enlarge your UDP max size.")
		}
	}
	if reply == nil || reply.Truncated || err != nil {
		rtt0 := rtt
		reply, rtt, err = s.TCPCli.Exchange(req, server)
		rtt += rtt0
		if err != nil {
			logger.WithError(err).Error("Fail to send TCP query.")
		}
	}

	return
}

// LookupMutation does the same as Lookup, with pointer mutation for DNS query.
// DNS Compression: https://tools.ietf.org/html/rfc1035#section-4.1.4
// DNS compression pointer mutation: https://gist.github.com/klzgrad/f124065c0616022b65e5#file-sendmsg-c-L30-L63
func (s *Server) LookupMutation(req *dns.Msg, server string) (reply *dns.Msg, rtt time.Duration, err error) {
	logger := logrus.WithFields(logrus.Fields{
		"question": questionString(&req.Question[0]),
		"server":   server,
	})
	// cleanEdns0(req)

	var (
		udpSize int
		buffer  []byte
	)
	if !s.TCPOnly {
		req := req.Copy()
		udpSize = setUDPSize(req, s.UDPMaxSize)
		buffer, err = req.Pack()
	} else {
		buffer, err = req.Pack()
	}
	if err != nil {
		return nil, 0, errors.Wrap(err, "fail to pack request")
	}
	buffer = mutateQuestion(buffer)

	t := time.Now()
	if !s.TCPOnly {
		ddl := t.Add(s.UDPCli.Timeout)
		reply, err = rawLookup(s.UDPCli, req.Id, buffer, server, ddl, uint16(udpSize))
		if err != nil {
			logger.WithError(err).Error("Fail to send UDP mutation query. Will retry in TCP.")
		}
		if reply != nil && reply.Truncated {
			logger.Error("Truncated msg received. Will retry in TCP. Consider enlarge your UDP max size.")
		}
	}

	if reply == nil || reply.Truncated || err != nil {
		ddl := time.Now().Add(s.TCPCli.Timeout)
		reply, err = rawLookup(s.TCPCli, req.Id, buffer, server, ddl, 0)
		if err != nil {
			logger.WithError(err).Error("Fail to send TCP mutation query.")
		}
	}

	rtt = time.Since(t)
	return
}

func rawLookup(cli *dns.Client, id uint16, req []byte, server string, ddl time.Time, udpSize uint16) (*dns.Msg, error) {
	conn, err := cli.Dial(server)
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

func setUDPSize(req *dns.Msg, size int) int {
	if size <= dns.MinMsgSize {
		return dns.MinMsgSize
	}
	// https://tools.ietf.org/html/rfc6891#section-6.2.5
	if e := req.IsEdns0(); e != nil {
		if e.UDPSize() >= uint16(size) {
			return int(e.UDPSize())
		}
		e.SetUDPSize(uint16(size))
		return size
	}
	req.SetEdns0(uint16(size), false)
	return size
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
