# Coraza WAF Caddy Module

[![Tests](https://github.com/corazawaf/coraza-caddy/actions/workflows/tests.yml/badge.svg)](https://github.com/corazawaf/coraza-caddy/actions/workflows/tests.yml)
<a href="https://pkg.go.dev/github.com/corazawaf/coraza-caddy" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

[OWASP Coraza](https://github.com/corazawaf/coraza) Caddy Module provides Web Application Firewall capabilities for Caddy.

OWASP Coraza WAF is 100% compatible with OWASP Coreruleset and Modsecurity syntax.

## Getting started

`go run mage.go -l` lists all the available commands:

```bash
▶ go run mage.go -l
Targets:
  buildCaddy        builds the plugin.
  buildCaddyLinux   builds the plugin with GOOS=linux.
  buildExample       builds the example deployment.
  check              runs lint and tests.
  coverage           runs tests with coverage and race detector enabled.
  doc                runs godoc, access at http://localhost:6060
  e2e                runs e2e tests with a built plugin against the example deployment.
  format             formats code in this repository.
  ftw                runs CRS regressions tests.
  lint               verifies code quality.
  precommit          installs a git hook to run check when committing
  reloadExample      reload the test environment.
  runExample         spins up the test environment, access at http://localhost:8080.
  teardownExample    tears down the test environment.
  test               runs all tests.
```

## Plugin syntax

```caddy
coraza_waf {
 directives `
  Include /path/to/config.conf
  SecAction "id:1,pass,log"
 `
}
```

Sample usage:  

**Important:** `order coraza_waf first` must be always included in your Caddyfile for Coraza module to work

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
   Include file1.conf 
   Include file2.conf
   Include /some/path/*.conf
  `
 }
 reverse_proxy http://192.168.1.15:8080
}
```

## Build Caddy with Coraza WAF

Run:

```shell
xcaddy build --with github.com/corazawaf/coraza-caddy/v2
```

## Testing

You may run the test suite by executing:

```shell
go run mage.go test
```

## Using OWASP Core Ruleset

You can load OWASP CRS by passing the field `load_owasp_crs` and then load the CRS files in the directives as described in the [coraza-coreruleset](https://github.com/corazawaf/coraza-coreruleset/v4) documentation.

```caddy
:8080 {
 coraza_waf {
  load_owasp_crs
  directives `
   Include @coraza.conf-recommended
   Include @crs-setup.conf.example
   Include @owasp_crs/*.conf
   SecRuleEngine On
  `
 }

 reverse_proxy httpbin:8081
}
```

## Running Example

### Docker

```bash
go run mage.go buildExample runExample
curl -i localhost:8080/
```

### Local

```bash
# in terminal 1
go run github.com/mccutchen/go-httpbin/v2/cmd/go-httpbin@v2.9.0 -port 8081

# in terminal 2
go run mage.go buildCaddy
./build/caddy run --config example/Caddyfile --adapter caddyfile

# in terminal 3
curl -i localhost:8080/
```

## Respond with custom message or HTML page

In order to respond with a custom message or HTML page, you can take advantage of [handle_errors](https://caddyserver.com/docs/caddyfile/directives/handle_errors) directive:

```caddy
handle_errors 403 {
 header X-Blocked "true"
 respond "Your request was blocked. Request ID: {http.request.header.x-request-id}"
}
```
or
```caddy
handle_errors {
 @block_codes `{err.status_code} in [403]`
 handle @block_codes {
  root    * /path/to/html/dir
  rewrite * /{err.status_code}.html
  file_server
 }
}
```

It is possible to use the [templates](https://caddyserver.com/docs/caddyfile/directives/templates) directive to render data dynamically. Take a look at [`example/403.html`](./example/403.html) file.  
