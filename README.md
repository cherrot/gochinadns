# GoChinaDNS

GoChinaDNS is a DNS proxy, which smartly dispatches DNS questions to get nearest answers. This can be a drop-in replacement for [ChinaDNS](https://github.com/shadowsocks/ChinaDNS), with a better code implementation and several bugfixes.

## Install

This project is written in Go. To build it, you need [install Go](https://golang.org/doc/install) at first.

Build:

```shell
cd cmd/chinadns
go build
```

Run:

```shell
./chinadns -p 5553 -c ./china.list -v
```

Test:

```shell
dig @::1 -p5553 google.com
```

## Params
```
$ ./chinadns -h

Usage of ./chinadns:
  -V    Print version and exit.
  -b string
        Bind address. (default "::")
  -c string
        Path to China route list. Both IPv4 and IPv6 are supported. See http://ipverse.net (default "./china.list")
  -d    Drop results of trusted servers which containing IPs in China. (Bidirectional mode.) (default true)
  -domain-blacklist string
        Path to domain blacklist file.
  -domain-polluted string
        Path to polluted domains list. Queries of these domains will not be sent to DNS in China.
  -force-tcp
        Force DNS queries use TCP only.
  -l string
        Path to IP blacklist file.
  -m    Enable compression pointer mutation in DNS queries.
  -p int
        Listening port. (default 53)
  -reuse-port
        Enable SO_REUSEPORT to gain some performance optimization. Need Linux>=3.9 (default true)
  -s value
        Upstream DNS servers. Need China route list to check whether it's a trusted server or not. (default 119.29.29.29,114.114.114.114)
  -test-domains string
        Domain names to test DNS connection health. (default "qq.com,163.com")
  -timeout duration
        DNS request timeout (default 1s)
  -trusted-servers value
        Servers which (located in China but) can be trusted. (default 193.112.15.186:2323)
  -udp-max-bytes int
        Default DNS max message size on UDP. (default 1410)
  -v    Enable verbose logging.
  -y float
        Delay (in seconds) to query another DNS server when no reply received. (default 0.1)
```
