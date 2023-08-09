FROM debian

COPY e2e/Caddyfile /etc/caddy/Caddyfile

COPY build/caddy-linux /usr/bin/caddy

CMD ["/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
