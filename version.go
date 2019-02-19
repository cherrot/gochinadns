package gochinadns

import "fmt"

const (
	name    = "GoChinaDNS"
	version = "v1.0"
)

// GetVersion returns server version.
func GetVersion() string {
	return fmt.Sprintf("%s %s", name, version)
}
