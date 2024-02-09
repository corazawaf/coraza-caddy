# Copyright 2024 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM debian

COPY e2e/Caddyfile /etc/caddy/Caddyfile

COPY build/caddy-linux /usr/bin/caddy

CMD ["/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
