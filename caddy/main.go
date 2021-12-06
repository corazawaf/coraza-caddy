package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/jptosso/coraza-caddy"

	// You may uncomment the following lines to enable libinjection and pcre plugins
	_ "github.com/jptosso/coraza-libinjection"
	_ "github.com/jptosso/coraza-pcre"
)

func main() {
	caddycmd.Main()
}
