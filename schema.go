package gochinadns

import (
	"fmt"
	"github.com/pkg/errors"
	"strings"
)

// resolver contains info about a single upstream DNS server.
type resolver struct {
	addr      string   //address of the resolver in format ip:port
	protocols []string //list of protocols to use with this resolver, in order of execution
}

func (r resolver) GetAddr() string {
	return r.addr
}

func (r resolver) GetProtocols() []string {
	return r.protocols
}

func (r resolver) String() string {
	return r.GetAddr()
}

// resolverArray is just an array of type resolver.
// It's not really required other than to define String() to print it nicely in the log.
type resolverArray []resolver

func (r resolverArray) String() string {
	sb := new(strings.Builder)
	for _, server := range r {
		sb.WriteString(fmt.Sprintf("%s%s ", server.GetProtocols(), server.GetAddr()))
	}
	return sb.String()
}

// schemaToResolver takes a single resolver in schema format and outputs a resolver struct.
// Will also accept regular ip:port format for backwards compatibility.
// The schema is defined as:  protocol[+protocol]@ip:port
func schemaToResolver(input string, tcpOnly bool) (r resolver, err error) {
	err = nil
	fields := strings.Split(input, "@")
	if len(fields) == 1 { // input is ip:port
		var proto []string
		if tcpOnly {
			proto = []string{"tcp"}
		} else {
			proto = []string{"udp", "tcp"}
		}
		r = resolver{
			addr:      fields[0],
			protocols: proto,
		}
		return
	} else { //input is schema
		//extract protocols
		pr := strings.Split(strings.ToLower(fields[0]), "+")
		var proto []string
		// check if the protocols are valid
		for _, protocol := range pr {
			er := checkProtocol(protocol)
			if er != nil {
				err = errors.Wrapf(er, "Error in resolver [%s]", input)
				return
			}
			proto = uniqueAppendString(proto, protocol)
		}
		r = resolver{
			addr:      fields[1],
			protocols: proto,
		}
		return
	}
}

// checkProtocol checks if a valid protocol is specified.
func checkProtocol(p string) error {
	if p == "udp" || p == "tcp" {
		return nil
	} else {
		return errors.Errorf("Unknown protocol [%s]", p)
	}
}
