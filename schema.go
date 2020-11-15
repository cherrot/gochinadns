package gochinadns

import (
	"github.com/pkg/errors"
	"strings"
)

// schemaToResolver takes a single resolver in schema format and outputs a resolver struct.
// Will also accept regular ip:port format for backwards compatibility.
// The schema is defined as:  protocol[+protocol]@ip:port
func schemaToResolver(input string) (r resolver, err error) {
	err = nil
	fields := strings.Split(input, "@")
	if len(fields) > 1 { //input is schema
		//extract protocols
		pr := strings.Split(strings.ToLower(fields[0]), "+")
		var proto []string
		// check if the protocols are valid
		for _, protocol := range pr {
			er := checkProtocol(protocol)
			if er != nil {
				r = resolver{
					addr:  "",
					proto: []string{},
				}
				err = errors.Wrapf(er, "Error in resolver [%s]", input)
				return
			}
			proto = uniqueAppendString(proto, protocol)
		}
		r = resolver{
			addr:  fields[1],
			proto: proto,
		}
		return
	} else { // input is ip:port
		r = resolver{
			addr:  fields[0],
			proto: []string{"udp", "tcp"},
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
