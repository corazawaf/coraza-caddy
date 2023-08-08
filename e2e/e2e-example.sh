#!/bin/bash
# Copyright 2023 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0
CADDY_HOST=${CADDY_HOST:-"localhost:8080"}
HTTPBIN_HOST=${HTTPBIN_HOST:-"localhost:8081"}

go run github.com/corazawaf/coraza/v3/http/e2e/cmd/httpe2e@main --proxy-hostport "http://${CADDY_HOST}" --httpbin-hostport "http://${HTTPBIN_HOST}"
