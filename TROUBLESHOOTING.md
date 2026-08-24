# Troubleshooting
### The WAF Configuration is not reloaded on Caddy reload
By design, Caddy compares the new configuration with the old one when reloads occur. 
If the old config is 100% identical to the new one, it skips the reload operation because there is no need to change the config.

> 📝 Caddy compares the modified JSON, not the initial Caddyfile (or any other adapter configuration). Hence, any comments, snippets (including their names and structure), and similar elements are exclusively understood by the Caddyfile adapter. Alterations to snippet names or comments do not qualify as modifications in the resulting JSON configuration.

Thus, modifying a line within a custom imported WAF configuration file will have no impact on Caddy's JSON configuration, which will remain unchanged. As an example, consider the following lines within your Caddyfile configuration:

```caddy
coraza_waf {
 directives `
  Include /path/to/config.conf
 `
}
```
In this scenario, modifying lines in `/path/to/config.conf` will not alter the Caddy configuration itself. Consequently, any added or removed rules will not be recognized by the module.\
\
A configuration reload can be enforced by utilizing `caddy reload --force` or, in case you are using APIs, by specifying the `Cache-Control: must-revalidate` header. This forces the reload process regardless of whether any modifications were made. Further details can be found in the official Caddy documentation [here](https://caddyserver.com/docs/api#post-load).

### Memory growth during HTTP/2 HPACK bomb tests
`coraza-caddy` receives requests only after Caddy has parsed HTTP headers. This means HPACK decompression behavior and memory usage limits are handled at the Caddy HTTP server layer, not inside the Coraza middleware.

If you need to harden against HPACK bomb-style traffic, configure limits on the Caddy server, for example:

```caddy
{
	servers {
		max_header_size 16KiB
	}
}
```

Note the Caddyfile option is `max_header_size`; `max_header_bytes` is the corresponding key in Caddy's JSON config, and using that name in a Caddyfile is a parse error.

Use a value appropriate for your application. Lower values improve resilience to oversized/expanded headers, but may block legitimate requests with large cookies or header sets.
