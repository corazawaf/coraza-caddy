# Coraza WAF Caddy Module

[![Tests](https://github.com/corazawaf/coraza-caddy/actions/workflows/tests.yml/badge.svg)](https://github.com/corazawaf/coraza-caddy/actions/workflows/tests.yml)
<a href="https://pkg.go.dev/github.com/corazawaf/coraza-caddy" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

[OWASP Coraza](https://github.com/corazawaf/coraza) Caddy Module provides Web Application Firewall capabilities for Caddy.

OWASP Coraza WAF is 100% compatible with OWASP Coreruleset and Modsecurity syntax.

## Plugin syntax

```caddy
coraza_waf {
 directives `
  SecAction "id:1,pass,log"
 `
 include /path/to/config.conf
}
```

Sample usage:  
Important: `order coraza_waf first` must be always included in your Caddyfile for Coraza module to work

```caddy
{
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

```shell
xcaddy build --with github.com/corazawaf/coraza-caddy
```

## Testing

You may run the test suite by executing:

```shell
git clone https://github.com/corazawaf/coraza-caddy
cd coraza-caddy
go test ./...`
```

## Using OWASP Core Ruleset

Clone the [coreruleset repository](https://github.com/coreruleset/coreruleset) and download the default coraza configurations from [Coraza repository](https://raw.githubusercontent.com/corazawaf/coraza/v2/master/coraza.conf-recommended), then add the following to you coraza_waf directive:

```
include caddypath/coraza.conf-recommended
include caddypath/coreruleset/crs-setup.conf.example
include caddypath/coreruleset/rules/*.conf
```

## Known Issues

## FAQ
