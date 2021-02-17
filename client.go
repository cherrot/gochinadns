package gochinadns

import (
	"time"

	"github.com/miekg/dns"

	"github.com/cherrot/gochinadns/doh"
)

type Client struct {
	*clientOptions
	UDPCli    *dns.Client
	TCPCli    *dns.Client
	DoHCli    *doh.Client
}

func NewClient(opts ...ClientOption) *Client {
	o := new(clientOptions)
	for _, f := range opts {
		f(o)
	}
	return &Client{
		clientOptions: o,
		UDPCli:        &dns.Client{Timeout: o.Timeout, Net: "udp"},
		TCPCli:        &dns.Client{Timeout: o.Timeout, Net: "tcp"},
		DoHCli:        doh.NewClient(doh.WithTimeout(o.Timeout)),
	}
}

type clientOptions struct {
	Timeout          time.Duration // Timeout for one DNS query
	UDPMaxSize       int           // Max message size for UDP queries
	TCPOnly          bool          // Use TCP only
	Mutation         bool          // Enable DNS pointer mutation for trusted servers
}

type ClientOption func(*clientOptions)

func WithTimeout(t time.Duration) ClientOption {
	return func(o *clientOptions) {
		o.Timeout = t
	}
}

func WithUDPMaxBytes(max int) ClientOption {
	return func(o *clientOptions) {
		o.UDPMaxSize = max
	}
}

func WithTCPOnly(b bool) ClientOption {
	return func(o *clientOptions) {
		o.TCPOnly = b
	}
}

func WithMutation(b bool) ClientOption {
	return func(o *clientOptions) {
		o.Mutation = b
	}
}
