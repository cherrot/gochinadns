package doh

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const DoHMediaType = "application/dns-message"

var ErrQueryMyself = errors.New("not allowed to query myself")

type clientOptions struct {
	Timeout         time.Duration
	SkipQueryMyself bool
}

type ClientOption func(*clientOptions)

// WithTimeout set a DNS query timeout
func WithTimeout(t time.Duration) ClientOption {
	return func(o *clientOptions) {
		o.Timeout = t
	}
}

// WithSkipQueryMySelf controls whether sending DNS request of DoH server's domain to itself.
// Suppose we have a DoH client for https://dns.google.com/query, when this option is set,
// a DNS request whose question is dns.google.com will get an ErrQueryMyself.
// This is useful when this client acts as a local DNS resolver.
func WithSkipQueryMySelf(skip bool) ClientOption {
	return func(o *clientOptions) {
		o.SkipQueryMyself = skip
	}
}

type Client struct {
	opt *clientOptions
	cli *http.Client
}

func NewClient(opts ...ClientOption) *Client {
	o := new(clientOptions)
	for _, f := range opts {
		f(o)
	}
	return &Client{
		opt: o,
		cli: &http.Client{
			Timeout: o.Timeout,
		},
	}
}

func (c *Client) Exchange(req *dns.Msg, address string) (r *dns.Msg, rtt time.Duration, err error) {
	var (
		buf, b64 []byte
		begin    = time.Now()
		origID   = req.Id
	)

	if c.opt.SkipQueryMyself {
		u, e := url.Parse(address)
		if e != nil {
			return nil, 0, e
		}
		if req.Question[0].Name == dns.Fqdn(u.Hostname()) {
			return nil, 0, ErrQueryMyself
		}
	}

	// Set DNS ID as zero accoreding to RFC8484 (cache friendly)
	req.Id = 0
	buf, err = req.Pack()
	b64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(buf)))
	if err != nil {
		return
	}
	base64.RawURLEncoding.Encode(b64, buf)

	// No need to use hreq.URL.Query()
	uri := address + "?dns=" + string(b64)
	logrus.Debugln("DoH request:", uri)
	hreq, _ := http.NewRequest("GET", uri, nil)
	hreq.Header.Add("Accept", DoHMediaType)
	resp, err := c.cli.Do(hreq)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = errors.New("DoH query failed: " + string(content))
		return
	}

	r = new(dns.Msg)
	err = r.Unpack(content)
	r.Id = origID
	rtt = time.Since(begin)
	return
}
