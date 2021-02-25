package gochinadns

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	supportedProtocols   = []string{"udp", "tcp", "doh"}
	supportedProtocolMap = make(map[string]bool)

	ErrUnknowProtocol = errors.New("unknown protocol")
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
// The schema is defined as:  [protocol[+protocol]@]ip[:port]
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
			protos = []string{"udp", "tcp"}
		}
	} else { // schema in proto[+proto2]@ip[:port] format
		addr = fields[1]
		//extract protocols
		ps := strings.Split(strings.ToLower(fields[0]), "+")
		// check if the protocols are valid
		for _, protocol := range ps {
			err = checkProtocol(protocol)
			if err != nil {
				return
			}
			protos = uniqueAppendString(protos, protocol)
		}
	}

	// Process host port
	if len(addr) > 0 && addr[0] == '[' {
		if _, _, err = net.SplitHostPort(addr); err != nil {
			if strings.Contains(err.Error(), "missing port in address") {
				addr = addr + ":53"
				err = nil
				if _, _, err = net.SplitHostPort(addr); err != nil {
					return
				}
			} else {
				return
			}
		}
	} else if _, _, err = net.SplitHostPort(addr); err != nil {
		if strings.Contains(err.Error(), "missing port in address") ||
			strings.Contains(err.Error(), "too many colons in address") {
			addr, err = net.JoinHostPort(addr, "53"), nil
		} else {
			return
		}
	}

	r = &Resolver{
		Addr:      addr,
		Protocols: protos,
	}
	return
}

// checkProtocol checks if a valid protocol is specified.
func checkProtocol(proto string) error {
	if _, ok := supportedProtocolMap[proto]; ok {
		return nil
	}
	return fmt.Errorf("%w [%s]", ErrUnknowProtocol, proto)
}
