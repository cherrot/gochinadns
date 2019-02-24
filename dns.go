package gochinadns

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
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
	uctx, ucancel := context.WithCancel(ctx)
	tctx, tcancel := context.WithCancel(ctx)
	go func() {
		<-uctx.Done()
		<-tctx.Done()
		cancel()
	}()

	trusted := make(chan *dns.Msg, 1)
	untrusted := make(chan *dns.Msg, 1)
	if s.Mutation {
		go lookupInServers(tctx, tcancel, trusted, req, s.TrustedServers, s.Delay, s.LookupMutation)
	} else {
		go lookupInServers(tctx, tcancel, trusted, req, s.TrustedServers, s.Delay, s.Lookup)
	}
	if !s.DomainPolluted.Contain(qName) {
		go lookupInServers(uctx, ucancel, untrusted, req, s.UntrustedServers, s.Delay, s.Lookup)
	} else {
		ucancel()
	}

	select {
	case rep := <-untrusted:
		reply = s.processReply(ctx, logger, rep, trusted, s.processUntrustedAnswer)
	case rep := <-trusted:
		reply = s.processReply(ctx, logger, rep, untrusted, s.processTrustedAnswer)
	case <-ctx.Done():
	}
	// notify lookupInServers to quit.
	cancel()

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

func (s *Server) processReply(
	ctx context.Context, logger *logrus.Entry, rep *dns.Msg, other <-chan *dns.Msg,
	process func(context.Context, *logrus.Entry, *dns.Msg, net.IP, <-chan *dns.Msg) *dns.Msg,
) (reply *dns.Msg) {
	reply = rep
	for i, rr := range rep.Answer {
		switch answer := rr.(type) {
		case *dns.A:
			return process(ctx, logger, rep, answer.A, other)
		case *dns.AAAA:
			return process(ctx, logger, rep, answer.AAAA, other)
		case *dns.CNAME:
			if i < len(rep.Answer)-1 {
				continue
			}
			logger.Debug("CNAME to ", answer.Target)
			return
		default:
			return
		}
	}
	return
}

func (s *Server) processUntrustedAnswer(ctx context.Context, logger *logrus.Entry, rep *dns.Msg, answer net.IP, trusted <-chan *dns.Msg) (reply *dns.Msg) {
	reply = rep
	logger = logger.WithField("answer", answer)

	hit, err := s.IPBlacklist.Contains(answer)
	if err != nil {
		logger.WithError(err).Error("Blacklist CIDR error.")
	}
	if hit {
		logger.Debug("Answer hit blacklist. Wait for trusted reply.")
	} else {
		contain, err := s.ChinaCIDR.Contains(answer)
		if err != nil {
			logger.WithError(err).Error("CIDR error.")
		}
		if contain {
			logger.Debug("Answer belongs to China. Use it.")
			return
		}
		logger.Debug("Answer is overseas. Wait for trusted reply.")
	}

	select {
	case rep := <-trusted:
		reply = s.processReply(ctx, logger, rep, nil, s.processTrustedAnswer)
	case <-ctx.Done():
		logger.Warn("No trusted reply. Use this as fallback.")
	}
	return
}

func (s *Server) processTrustedAnswer(ctx context.Context, logger *logrus.Entry, rep *dns.Msg, answer net.IP, untrusted <-chan *dns.Msg) (reply *dns.Msg) {
	reply = rep
	logger = logger.WithField("answer", answer)

	hit, err := s.IPBlacklist.Contains(answer)
	if err != nil {
		logger.WithError(err).Error("Blacklist CIDR error.")
	}
	if hit {
		logger.Debug("Answer hit blacklist. Wait for trusted reply.")
	} else {
		if !s.Bidirectional {
			logger.Debug("Answer is trusted. Use it.")
			return
		}

		contain, err := s.ChinaCIDR.Contains(answer)
		if err != nil {
			logger.WithError(err).Error("CIDR error.")
		}
		if !contain {
			logger.Debug("Answer is trusted and overseas. Use it.")
			return
		}
		logger.Debug("Answer may not be the nearest. Wait for untrusted reply.")
	}

	select {
	case rep := <-untrusted:
		reply = s.processReply(ctx, logger, rep, nil, s.processUntrustedAnswer)
	case <-ctx.Done():
		logger.Debug("No untrusted reply. Use this as fallback.")
	}
	return
}
