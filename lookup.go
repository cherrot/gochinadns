package gochinadns

import (
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// LookupFunc looks up DNS request to the given server and returns DNS reply, its RTT time and an error.
type LookupFunc func(request *dns.Msg, server Resolver) (reply *dns.Msg, rtt time.Duration, err error)

func (c *Client) Lookup(req *dns.Msg, server Resolver) (reply *dns.Msg, rtt time.Duration, err error) {
	if c.Mutation {
		return c.lookupMutation(req, server)
	}
	return c.lookupNormal(req, server)
}

// lookupNormal send a DNS request to the specific server and get its corresponding reply.
// DNS Proxy Implementation Guidelines: https://tools.ietf.org/html/rfc5625
// DNS query processing: https://tools.ietf.org/html/rfc1034#section-3.7
// Happy Eyeballs: https://tools.ietf.org/html/rfc6555#section-5.4 and #section-6
func (c *Client) lookupNormal(req *dns.Msg, server Resolver) (reply *dns.Msg, rtt time.Duration, err error) {
	logger := logrus.WithFields(logrus.Fields{
		"question": questionString(&req.Question[0]),
		"server":   server,
	})

	var rtt0 time.Duration

	for _, protocol := range server.GetProtocols() {
		switch protocol {
		case "udp":
			logger.Debug("Query upstream udp")
			reply, rtt0, err = c.UDPCli.Exchange(req, server.GetAddr())
			rtt += rtt0
			if err == nil {
				return
			}
			logger.WithError(err).Error("Fail to send UDP query.")
			if reply != nil && reply.Truncated {
				logger.Error("Truncated msg received. Consider enlarge your UDP max size.")
			}
		case "tcp":
			logger.Debug("Query upstream tcp")
			reply, rtt0, err = c.TCPCli.Exchange(req, server.GetAddr())
			rtt += rtt0
			if err == nil {
				return
			}
			logger.WithError(err).Error("Fail to send TCP query.")
		default:
			logger.Errorf("No available protocols for resolver %s", server)
			return
		}
	}
	return
}

// lookupMutation does the same as lookupNormal, with pointer mutation for DNS query.
// DNS Compression: https://tools.ietf.org/html/rfc1035#section-4.1.4
// DNS compression pointer mutation: https://gist.github.com/klzgrad/f124065c0616022b65e5#file-sendmsg-c-L30-L63
func (c *Client) lookupMutation(req *dns.Msg, server Resolver) (reply *dns.Msg, rtt time.Duration, err error) {
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

	// FIXME: may cause unexpected timeout (especially in `proto1+proto2@addr` case)
	t := time.Now()
	for _, protocol := range server.GetProtocols() {
		switch protocol {
		case "udp":
			logger.Debug("Query upstream udp")
			ddl := t.Add(c.UDPCli.Timeout)
			udpSize := getUDPSize(req)
			reply, err = rawLookup(c.UDPCli, req.Id, buffer, server, ddl, udpSize)
			if err == nil {
				rtt = time.Since(t)
				return
			}
			logger.WithError(err).Error("Fail to send UDP mutation query. ")
			if reply != nil && reply.Truncated {
				logger.Error("Truncated msg received. Consider enlarge your UDP max size.")
			}
		case "tcp":
			logger.Debug("Query upstream tcp")
			ddl := time.Now().Add(c.TCPCli.Timeout)
			reply, err = rawLookup(c.TCPCli, req.Id, buffer, server, ddl, 0)
			if err == nil {
				rtt = time.Since(t)
				return
			}
			logger.WithError(err).Error("Fail to send TCP mutation query.")
		default:
			logger.Errorf("No available protocols for resolver %s", server)
			return
		}
	}
	rtt = time.Since(t)
	return
}

func rawLookup(cli *dns.Client, id uint16, req []byte, server Resolver, ddl time.Time, udpSize uint16) (*dns.Msg, error) {
	conn, err := cli.Dial(server.GetAddr())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.UDPSize = udpSize

	_ = conn.SetWriteDeadline(ddl)
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(ddl)
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

//nolint:deadcode,unused
func cleanEdns0(req *dns.Msg) {
	for {
		if req.IsEdns0() == nil {
			break
		}
		req.Extra = req.Extra[:len(req.Extra)-1]
	}
}

//nolint:deadcode,unused
func mutateQuestion(raw []byte) []byte {
	length := len(raw)
	if length <= 16 {
		return raw
	}

	offset := 12
	for offset < length-4 {
		if raw[offset]&0xC0 != 0 {
			return raw
		}
		if raw[offset] == 0 {
			break
		}
		offset += int(raw[offset]) + 1
	}

	mutation := make([]byte, length+1)
	copy(mutation, raw[:offset])
	mutation[offset], mutation[offset+1] = 0xC0, 0x07
	copy(mutation[offset+2:], raw[offset+1:])
	return mutation
}

// add a "pointer" question. does not work now.
//nolint:deadcode,unused
func mutateQuestion2(raw []byte) []byte {
	length := len(raw)
	if length <= 16 {
		return raw
	}

	var (
		offset = 12
		virus  = make([]byte, 6)
	)
	for offset < length-4 {
		if raw[offset] == 0 {
			virus[0], virus[1] = 0xC0, 0x12
			copy(virus[2:], raw[offset+1:])
			break
		}
		offset += int(raw[offset]) + 1
	}

	mutation := make([]byte, length+6)
	copy(mutation, raw[:12])
	mutation[5]++
	copy(mutation[12:], virus)
	copy(mutation[18:], raw[12:])
	return mutation
}

func questionString(q *dns.Question) string {
	return q.Name + " " + dns.TypeToString[q.Qtype]
}
