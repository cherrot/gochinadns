package gochinadns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Serve serves DNS request.
func (s *Server) Serve(w dns.ResponseWriter, req *dns.Msg) {
	// Its client's responsibility to close this conn.
	// defer w.Close()
	var reply *dns.Msg

	start := time.Now()
	qName := req.Question[0].Name
	logger := logrus.WithField("question", questionString(&req.Question[0]))

	if s.DomainBlacklist.Contain(qName) {
		reply = new(dns.Msg)
		reply.SetReply(req)
		w.WriteMsg(reply)
		return
	}

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()
	trusted := make(chan *dns.Msg, 1)
	untrusted := make(chan *dns.Msg, 1)
	if s.Mutation {
		go lookupInServers(ctx, trusted, req, s.TrustedServers, s.Delay, s.LookupMutation)
	} else {
		go lookupInServers(ctx, trusted, req, s.TrustedServers, s.Delay, s.Lookup)
	}
	if !s.DomainPolluted.Contain(qName) {
		go lookupInServers(ctx, untrusted, req, s.UntrustedServers, s.Delay, s.Lookup)
	}

POLL:
	select {
	case rep, ok := <-untrusted:
		if !ok {
			logger.Debug("Untrusted result channel is closed. Use former reply (maybe empty).")
			break
		}

		reply = rep
		for i, rr := range rep.Answer {
			switch answer := rr.(type) {
			case *dns.A:
				logger := logger.WithField("answer", answer.A)
				contain, err := s.ChinaCIDR.Contains(answer.A)
				if err != nil {
					logger.WithError(err).Error("CIDR error.")
				}
				if contain {
					cancel()
					logger.Debug("Answer belongs to China. Use this as reply.")
					break POLL
				} else {
					logger.Debug("Answer may be polluted. Wait for trusted reply.")
					goto POLL
				}

			case *dns.AAAA:
				logger := logger.WithField("answer", answer.AAAA)
				contain, err := s.ChinaCIDR.Contains(answer.AAAA)
				if err != nil {
					logger.WithError(err).Error("CIDR error.")
				}
				if contain {
					cancel()
					logger.Debug("Answer belongs to China. Use this as reply.")
					break POLL
				} else {
					logger.Debug("Answer may be polluted. Wait for trusted reply.")
					goto POLL
				}
			case *dns.CNAME:
				if i < len(rep.Answer)-1 {
					continue
				}
				cancel()
				logger.Debug("CNAME to ", answer.Target)
			default:
				cancel()
				break POLL
			}
		}
		cancel()

	case rep, ok := <-trusted:
		if !ok {
			logger.Debug("Trusted result channel is closed. Use former reply (maybe empty).")
			break
		}

		for i, rr := range rep.Answer {
			switch answer := rr.(type) {
			case *dns.A:
				logger := logger.WithField("answer", answer.A)
				if !s.Bidirectional {
					cancel()
					reply = rep
					logger.Debug("Use this trusted answer as reply.")
					break POLL
				}

				contain, _ := s.ChinaCIDR.Contains(answer.A)
				if contain {
					if reply == nil {
						reply = rep
						logger.Debug("Answer may not be the best. Wait for unstrusted reply.")
						goto POLL
					} else {
						cancel()
						reply = rep
						logger.Warn("This answer belongs to China but the one from unstrusted servers does not. Use this as reply.")
						break POLL
					}
				} else {
					cancel()
					reply = rep
					logger.Debug("Use this trusted overseas answer as reply.")
					break POLL
				}

			case *dns.AAAA:
				logger := logger.WithField("answer", answer.AAAA)
				if !s.Bidirectional {
					cancel()
					reply = rep
					logger.Debug("Use this trusted answer as reply.")
					break POLL
				}

				contain, _ := s.ChinaCIDR.Contains(answer.AAAA)
				if contain {
					if reply == nil {
						reply = rep
						logger.Debug("Answer may not be the best. Wait for unstrusted reply.")
						goto POLL
					} else {
						cancel()
						reply = rep
						logger.Warn("This answer belongs to China but the one from unstrusted servers does not. Use this as reply.")
						break POLL
					}
				} else {
					cancel()
					reply = rep
					logger.Debug("Use this trusted overseas answer as reply.")
					break POLL
				}
			case *dns.CNAME:
				if i < len(rep.Answer)-1 {
					continue
				}
				cancel()
				logger.Debug("CNAME to ", answer.Target)
			default:
				cancel()
				reply = rep
				break POLL
			}
		}
		cancel()
	}

	if reply != nil {
		// https://github.com/miekg/dns/issues/216
		reply.Compress = true
	} else {
		reply = new(dns.Msg)
		reply.SetReply(req)
	}

	w.WriteMsg(reply)
	logger.Debug("SERVING RTT: ", time.Since(start))
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
	req.RecursionDesired = true

	if !s.TCPOnly {
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
	req.RecursionDesired = true
	if !s.TCPOnly {
		setUDPSize(req, s.UDPMaxSize)
	}

	buffer, err := req.Pack()
	if err != nil {
		return nil, 0, errors.Wrap(err, "fail to pack request")
	}
	buffer = mutateQuestion(buffer)

	t := time.Now()
	if !s.TCPOnly {
		var udpSize uint16
		// If EDNS0 is used use that for size.
		opt := req.IsEdns0()
		if opt != nil && opt.UDPSize() >= dns.MinMsgSize {
			udpSize = opt.UDPSize()
		}
		// Otherwise use the client's configured UDP size.
		if opt == nil && s.UDPCli.UDPSize >= dns.MinMsgSize {
			udpSize = s.UDPCli.UDPSize
		}

		ddl := t.Add(s.UDPCli.Timeout)
		reply, err = rawLookup(s.UDPCli, req.Id, buffer, server, ddl, udpSize)
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

func lookupInServers(
	ctx context.Context, result chan<- *dns.Msg, req *dns.Msg, servers []string, delay time.Duration,
	lookupFunc func(*dns.Msg, string) (*dns.Msg, time.Duration, error),
) {
	if len(servers) == 0 {
		close(result)
		return
	}

	var errChain error
	logger := logrus.WithField("question", questionString(&req.Question[0]))
	cctx, cancel := context.WithCancel(ctx)

	ticker := time.NewTicker(delay)
	defer ticker.Stop()
	queryNext := make(chan struct{}, len(servers))
	queryNext <- struct{}{}
	var wg sync.WaitGroup

	doLookup := func(idx int, server string) {
		defer wg.Done()
		logger := logger.WithField("server", server)

		reply, rtt, err := lookupFunc(req, server)
		if err != nil {
			errChain = errors.Wrapf(err, "%d", idx)
			queryNext <- struct{}{}
			return
		}

		cancel()
		select {
		case result <- reply:
			logger.Debug("Query RTT: ", rtt)
		default:
		}
	}

	for idx, server := range servers {
		select {
		case <-cctx.Done():
			return
		case <-queryNext:
			wg.Add(1)
			go doLookup(idx, server)
		case <-ticker.C:
			wg.Add(1)
			go doLookup(idx, server)
		}
	}

	wg.Wait()
	close(result)
	if errChain != nil {
		logger.WithError(errChain).Error("Error hanppens.")
	}
}

func rawLookup(cli *dns.Client, id uint16, req []byte, server string, ddl time.Time, udpSize uint16) (*dns.Msg, error) {
	conn, err := cli.Dial(server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.TsigSecret = cli.TsigSecret
	if udpSize > 0 {
		conn.UDPSize = uint16(udpSize)
	}

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

func setUDPSize(req *dns.Msg, size int) {
	if size > dns.MinMsgSize {
		// https://tools.ietf.org/html/rfc6891#section-6.2.5
		if e := req.IsEdns0(); e != nil {
			if e.UDPSize() < uint16(size) {
				e.SetUDPSize(uint16(size))
			}
		} else {
			req.SetEdns0(uint16(size), false)
		}
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
