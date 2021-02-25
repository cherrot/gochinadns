package gochinadns

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	supportedProtocols   = []string{"udp", "tcp", "doh"}
	supportedProtocolMap = make(map[string]bool)

	ErrUnknowProtocol  = errors.New("unknown protocol")
	ErrInvalidResolver = errors.New("invalid resolver address")
)

func init() {
	for _, proto := range supportedProtocols {
		supportedProtocolMap[proto] = true
	}
}

func SupportedProtocols() []string {
	return supportedProtocols
}

// Resolver contains info about a single upstream DNS server.
type Resolver struct {
	Addr      string   //address of the resolver in format ip:port
	Protocols []string //list of protocols to use with this resolver, in order of execution
}

func (r *Resolver) GetAddr() string {
	return r.Addr
}

func (r *Resolver) GetProtocols() []string {
	return r.Protocols
}

func (r *Resolver) String() string {
	sb := new(strings.Builder)
	sb.WriteString(strings.Join(r.Protocols, "+"))
	sb.WriteByte('@')
	sb.WriteString(r.Addr)
	return sb.String()
}

// resolverList is just an array of type resolver.
// It's not really required other than to define String() to print it nicely in the log.
type resolverList []*Resolver

func (r resolverList) String() string {
	sb := new(strings.Builder)
	for _, server := range r {
		sb.WriteString(fmt.Sprintf("%s%s ", server.GetProtocols(), server.GetAddr()))
	}
	return sb.String()
}

// ParseResolver takes a single resolver in schema string format and outputs a resolver struct.
// It also accept regular ip[:port] format for backwards compatibility.
// The schema is defined as:  [protocol[+protocol]@]host[:port][/endpoint]
func ParseResolver(schema string, tcpOnly bool) (r *Resolver, err error) {
	err = nil
	var (
		addr   string
		protos []string
	)
	fields := strings.Split(schema, "@")
	if len(fields) == 1 { // schema in ip[:port] format
		addr = fields[0]
		if tcpOnly {
			protos = []string{"tcp"}
		} else {
			protos = []string{"udp"}
		}
	} else { // schema in proto[+proto2]@host[:port][/endpoint] format
		addr = fields[1]
		//extract protocols
		ps := strings.Split(strings.ToLower(fields[0]), "+")
		// check if the protocols are valid
		for _, protocol := range ps {
			protos = uniqueAppendString(protos, protocol)
		}
	}

	// Process host port
	if _, _, err = net.SplitHostPort(addr); err != nil {
		if strings.Contains(err.Error(), "missing port in address") ||
			strings.Contains(err.Error(), "too many colons in address") {
			if strings.Contains(addr, "[") {
				return
			}
			addr, err = net.JoinHostPort(addr, "53"), nil
		} else {
			return
		}
	}

	// Check protocol-host pair
	for _, protocol := range protos {
		if err = checkProtocolHost(protocol, addr); err != nil {
			return
		}
	}

	r = &Resolver{
		Addr:      addr,
		Protocols: protos,
	}
	return
}

// checkProtocolHost checks if a valid protocol-host pair is specified.
func checkProtocolHost(proto, addr string) error {
	if _, ok := supportedProtocolMap[proto]; !ok {
		return fmt.Errorf("%w [%s]", ErrUnknowProtocol, proto)
	}
	var errInvalid = fmt.Errorf("%w [%s@%s]", ErrInvalidResolver, proto, addr)
	switch proto {
	case "udp", "tcp":
		// Only IP format is allowd for UDP and TCP DNS protocol
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil {
			return errInvalid
		}
	case "doh":
		u, err := url.Parse(addr)
		if err != nil {
			return err
		}
		if u.Host == "" {
			return errInvalid
		}
	}
	return nil
}
