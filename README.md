# GoChinaDNS

GoChinaDNS is a DNS proxy to avoid DNS poisoning in China. This can be a drop-in replacement for [ChinaDNS](https://github.com/shadowsocks/ChinaDNS), with a better code implementation and several bugfixes.

## Install

This project is written in Go. To build it, you need [install Go](https://golang.org/doc/install) at first.

Build:

```shell
cd cmd/chinadns
go build
```

Run:

```shell
./chinadns -listen '[::]:5553' -c ./china.list -v
```

Test:

```shell
dig @::1 -p5553 google.com
```
