# GoChinaDNS

GoChinaDNS is a DNS proxy, which smartly dispatches DNS questions to get nearest answers. This can be a drop-in replacement for [ChinaDNS](https://github.com/shadowsocks/ChinaDNS), with a better code implementation and several bugfixes.

## Install

Binaries for linux, windows and darwin (macOS) are available under Releases. 

You will also need a list of IP ranges in China, such as [@pexcn/chnroute.txt](https://raw.githubusercontent.com/pexcn/daily/gh-pages/chnroute/chnroute.txt).
## Build
This project is written in Go. If you want to build it yourself, you need to [install Go](https://golang.org/doc/install) first.

```shell
git clone https://github.com/cherrot/gochinadns
cd gochinadns
go get -u ./...
cd cmd/chinadns
go build
```

## Usage 
Run:

```shell
./chinadns -p 5553 -c ./china.list -v
```

Test:

```shell
dig @::1 -p5553 google.com
```

## Advanced usage 
### Customize upstream servers
```shell
./chinadns -p 5553 -c ./china.list -s 114.114.114.114,127.0.0.1:5353
```
In this example, `127.0.0.1:5353` is the trusted resolver and can be a local dns forwarder (e.g. `dnscrypt-proxy`).

**Note:** you still need to make sure that your trusted resolver is accessible through a secure channel otherwise your DNS will stilll get poisoned. 

### Specify resolver protocol
The default format for upstream resolvers is `ip:port` for backwards compatibility with ChinaDNS.
Resolvers can also be passed as `protocol[+protocol]@ip:port` where protocol is `udp` or `tcp`.
Protocols are dialed in the order they are written (left to right). 
The rightmost protocol acts as a fallback and will only be dialed if the leftmost fails.

For example, if the upstream resolver is a local dns forwarder on port 5353, it can be passed as `udp@127.0.0.1:5353`
because fallback to TCP is not necessary. 

Similarly, if you run a transparent TCP proxy that proxies traffic to 8.8.8.8 you could use `tcp@8.8.8.8`:

```shell
./chinadns -p 5553 -c ./china.list -s udp+tcp@114.114.114.114,udp@127.0.0.1:5353,tcp@8.8.8.8
```
## Params
```
$ ./chinadns -h

Usage of chinadns:
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
        Comma separated list of upstream DNS servers. Need China route list to check whether it's a trusted server or not.
        Servers can be in format ip:port or protocol[+protocol]@ip:port where protocol is udp or tcp.
        Protocols are used in the order they are defined (left to right).
        If empty, protocol defaults to udp+tcp and port defaults to 53.
        Examples: udp@8.8.8.8,udp+tcp@127.0.0.1:5353,1.1.1.1 (default udp+tcp@119.29.29.29,udp+tcp@114.114.114.114)
  -test-domains string
        Domain names to test DNS connection health. (default "qq.com,163.com")
  -timeout duration
        DNS request timeout (default 1s)
  -trusted-servers value
        Comma separated list of  servers which (located in China but) can be trusted.
        Uses the same format as -s.
  -udp-max-bytes int
        Default DNS max message size on UDP. (default 4096)
  -v    Enable verbose logging.
  -y float
        Delay (in seconds) to query another DNS server when no reply received. (default 0.1)

```
