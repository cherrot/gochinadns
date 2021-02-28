package hosts

import (
	"net"

	"github.com/goodhosts/hostsfile"
	"github.com/sirupsen/logrus"
)

var h hostsfile.Hosts

func init() {
	var err error
	if h, err = hostsfile.NewHosts(); err != nil {
		logrus.WithError(err).Warnln("Fail to parse local hosts file.")
	}
}

func Lookup(host string) net.IP {
	i := getHostnamePosition(host)
	if i == -1 {
		return nil
	}
	return net.ParseIP(h.Lines[i].IP)
}

// copied from package hostsfile
func getHostnamePosition(host string) int {
	for i := range h.Lines {
		line := h.Lines[i]
		if !line.IsComment() && line.Raw != "" {
			if itemInSlice(host, line.Hosts) {
				return i
			}
		}
	}

	return -1
}

// copied from package hostsfile
func itemInSlice(item string, list []string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}

	return false
}
