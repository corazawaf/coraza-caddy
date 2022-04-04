# Coraza WAF Caddy Module

[![Tests](https://github.com/corazawaf/coraza-caddy/actions/workflows/tests.yml/badge.svg)](https://github.com/corazawaf/coraza-caddy/actions/workflows/tests.yml)
<a href="https://pkg.go.dev/github.com/corazawaf/coraza-caddy" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
[![Project Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)

Coraza Caddy Module a WAF for your applications using FastCGI or reverse proxy.

## Prerequisites

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
		include file1.conf 
		include file2.conf
		include /some/path/*.conf
	}
	reverse_proxy http://192.168.1.15:8080
}
```

## Build Caddy with Coraza WAF

Run:

```
xcaddy build --with github.com/corazawaf/coraza-caddy
```

## Testing

You may run the test suite by executing:

```
$ git clone https://github.com/corazawaf/coraza-caddy
$ cd coraza-caddy
$ go test ./...`
```

## Compiling with CRS support

Uncomment the plugin github.com/coraza-pcre from caddy/main.go and then compile.

## Using OWASP Core Ruleset

Once you have enabled your plugin, you will have to clone coreruleset and download the default coraza configurations from [Coraza repository](https://raw.githubusercontent.com/corazawaf/coraza/v2/master/coraza.conf-recommended), then add the following to you coraza_waf directive:

```
include caddypath/coraza.conf-recommended
include caddypath/coreruleset/crs-setup.conf.example
include caddypath/coreruleset/rules/*.conf
```

## Known Issues


## FAQ

