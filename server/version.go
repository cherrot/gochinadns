package server

import "fmt"

const (
	name    = "GoChinaDNS"
	version = "BAD-VERSION"
)

// GetVersion returns server version.
func GetVersion() string {
	return fmt.Sprintf("%s %s", name, version)
}
