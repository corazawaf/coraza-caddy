#!/bin/sh
# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

cd /workspace

# Revisited from https://github.com/corazawaf/coraza-proxy-wasm/blob/main/ftw/tests.sh

step=1
total_steps=1
max_retries=15 # Seconds for the server reachability timeout
host=${1:-caddy}
health_url="http://${host}:8080"

# Testing if the server is up
echo "[$step/$total_steps] Testing application reachability"
status_code="000"
while [[ "$status_code" -eq "000" ]]; do
  status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null "$health_url")
  sleep 1
  echo -ne "[Wait] Waiting for response from $health_url. Timeout: ${max_retries}s   \r"
  let "max_retries--"
  if [[ "$max_retries" -eq 0 ]]; then
    echo "[Fail] Timeout waiting for response from $health_url, make sure the server is running."
    echo "Caddy Logs:" && cat /home/caddy/logs/caddy.log
    exit 1
  fi
done
if [[ "${status_code}" -ne "200" ]]; then
  echo "[Fail] Unexpected response with code ${status_code} from ${health_url}, expected 200."
  echo "Caddy Logs:" && cat /home/caddy/logs/caddy.log
  exit 1
fi
echo -e "\n[Ok] Got status code $status_code, expected 200. Ready to start."

FTW_CLOUDMODE=${FTW_CLOUDMODE:-false}

FTW_INCLUDE=$([ "${FTW_INCLUDE}" == "" ] && echo "" || echo "-i ${FTW_INCLUDE}")

/ftw run -d coreruleset/tests/regression/tests --config ftw.yml --read-timeout=10s --max-marker-retries=50 --cloud=$FTW_CLOUDMODE $FTW_INCLUDE || exit 1
