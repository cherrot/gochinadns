package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cherrot/gochinadns"
)

func main() {
	flag.Parse()
	if *flagVersion {
		fmt.Println(gochinadns.GetVersion())
		fmt.Printf("Go version: %s\n", runtime.Version())
		return
	}
	if *flagVerbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	listen := net.JoinHostPort(*flagBind, strconv.Itoa(*flagPort))
	opts := []gochinadns.ServerOption{
		gochinadns.WithListenAddr(listen),
		gochinadns.WithBidirectional(*flagBidirectional),
		gochinadns.WithReusePort(*flagReusePort),
		gochinadns.WithDelay(time.Duration(*flagDelay * float64(time.Second))),
		gochinadns.WithTrustedResolvers(*flagForceTCP, flagTrustedResolvers...),
		gochinadns.WithResolvers(*flagForceTCP, flagResolvers...),
		gochinadns.WithSkipRefineResolvers(*flagSkipRefine),
	}
	if *flagTestDomains != "" {
		opts = append(opts, gochinadns.WithTestDomains(strings.Split(*flagTestDomains, ",")...))
	}
	if *flagCHNList != "" {
		opts = append(opts, gochinadns.WithCHNList(*flagCHNList))
	}
	if *flagIPBlacklist != "" {
		opts = append(opts, gochinadns.WithIPBlacklist(*flagIPBlacklist))
	}
	if *flagDomainBlacklist != "" {
		opts = append(opts, gochinadns.WithDomainBlacklist(*flagDomainBlacklist))
	}
	if *flagDomainPolluted != "" {
		opts = append(opts, gochinadns.WithDomainPolluted(*flagDomainPolluted))
	}

	copts := []gochinadns.ClientOption{
		gochinadns.WithUDPMaxBytes(*flagUDPMaxBytes),
		gochinadns.WithTCPOnly(*flagForceTCP),
		gochinadns.WithMutation(*flagMutation),
		gochinadns.WithTimeout(*flagTimeout),
		gochinadns.WithDoHSkipQuerySelf(true),
	}

	client := gochinadns.NewClient(copts...)
	server, err := gochinadns.NewServer(client, opts...)
	if err != nil {
		panic(err)
	}

	runUntilCanceled(context.Background(), server.Run)
}

func runUntilCanceled(ctx context.Context, f func() error) {
	minGap := time.Millisecond * 100
	maxGap := time.Second * 16
	gap := minGap
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logrus.Errorf("%s:%s", r, string(debug.Stack()))
				}
			}()
			err := f()
			if err == nil {
				gap = minGap
			} else {
				logrus.WithError(err).Errorf("Fail to exec %s", getFunctionName(f))
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-time.After(gap):
		}
		gap = gap * 2
		if gap > maxGap {
			gap = maxGap
		}
	}
}

func getFunctionName(i interface{}) string {
	f := runtime.FuncForPC(reflect.ValueOf(i).Pointer())
	fn, ln := f.FileLine(f.Entry())
	return fmt.Sprintf("%s[%s:%d]", trimLocPrefix(f.Name()), trimLocPrefix(fn), ln)
}

func trimLocPrefix(s string) string {
	t := strings.SplitN(s, "gochinadns/", 2)
	if len(t) == 2 {
		return t[1]
	}
	return s
}
