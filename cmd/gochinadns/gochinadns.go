package main

import (
	"flag"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cherrot/gochinadns/server"
)

var (
	flagVersion = flag.Bool("V", false, "Print version and exit.")
	flagVerbose = flag.Bool("v", false, "Enable verbose logging.")
)

// flag.Parse()
// LoadAndTestConfig
// RunServer
func main() {
	flag.Parse()
	if *flagVersion {
		fmt.Println(server.GetVersion())
		return
	}
	if *flagVerbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	s, err := server.New()
	if err != nil {
		panic(err)
	}
	panic(s.Run())
}
