# Coraza WAF Caddy Module

<a href="https://github.com/jptosso/coraza-caddy/actions/" target="_blank"><img src="https://github.com/jptosso/coraza-caddy/workflows/regression/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/jptosso/coraza-caddy" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
[![Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)

Coraza Caddy Module provides SecRule compatibility for your web applications deployed using Caddy.

## Prerequisites

[(See Coraza Documentation)](https://github.com/jptosso/coraza-waf#prerequisites)

* [Xcaddy](https://github.com/caddyserver/xcaddy#install)
* [Golang 1.16+](https://golang.org/doc/install)
* Linux Operating system (Coraza does not support Windows)

## Plugin syntax

Important: `order coraza_waf first` must be always included in your Caddyfile for Coraza module to work
```
coraza {
	directives `
		SecAction "id:1,pass,log"
	`
	include /path/to/config.conf
}
```

Sample usage:

```
{
    auto_https off
    order coraza_waf first
}

http://127.0.0.1:8080 {
	coraza_waf {
		directives `
			SecAction "id:1,pass,log"
			SecRule REQUEST_URI "/test5" "id:2, deny, log, phase:1"
			SecRule REQUEST_URI "/test6" "id:4, deny, log, phase:3"
		`
		include file1.conf file2.conf /some/path/*.conf
	}
	reverse_proxy http://192.168.1.15:8080
}
```

## Build Caddy with Coraza WAF

Run:

```
xcaddy build --with github.com/jptosso/coraza-caddy
```

## Testing

You may run the test suite by executing:

```
$ git clone https://github.com/jptosso/coraza-caddy
$ cd coraza-caddy
$ CGO_ENABLED go test ./...`
```

## Known Issues


## FAQ

