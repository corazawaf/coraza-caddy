#!/bin/bash
# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0
# Copied from https://github.com/corazawaf/coraza-proxy-wasm/tree/main/e2e
ENVOY_HOST=${ENVOY_HOST:-"localhost:8080"}
HTTPBIN_HOST=${HTTPBIN_HOST:-"localhost:8081"}
TIMEOUT_SECS=${TIMEOUT_SECS:-5}

[[ "${DEBUG}" == "true" ]] && set -x

# if env variables are in place, default values are overridden
health_url="http://${HTTPBIN_HOST}"
envoy_url_unfiltered="http://${ENVOY_HOST}"
envoy_url_filtered="${envoy_url_unfiltered}/admin"
envoy_url_filtered_resp_header="${envoy_url_unfiltered}/status/406"
envoy_url_echo="${envoy_url_unfiltered}/anything"

tueNegativeBodyPayload="This is a payload"
truePositiveBodyPayload="maliciouspayload"
trueNegativeBodyPayloadForResponseBody="Hello world"
truePositiveBodyPayloadForResponseBody="responsebodycode"

# wait_for_service waits until the given URL returns a 200 status code.
# $1: The URL to send requests to.
# $2: The max number of requests to send before giving up.
function wait_for_service() {
    local status_code="000"
    local url=${1}
    local max=${2}
    while [[ "${status_code}" -ne "200" ]]; do
      status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null "${url}")
      sleep 1
      echo -ne "[Wait] Waiting for response from ${url}. Timeout: ${max}s   \r"
      ((max-=1))
      if [[ "${max}" -eq 0 ]]; then
        echo "[Fail] Timeout waiting for response from ${url}, make sure the server is running."
        exit 1
      fi
    done
    echo -e "\n[Ok] Got status code ${status_code}"
}

# check_status sends HTTP requests to the given URL and expects a given response code.
# $1: The URL to send requests to.
# $2: The expected status code.
# $3-N: The rest of the arguments will be passed to the curl command as additional arguments
#       to customize the HTTP call.
function check_status() {
    local url=${1}
    local status=${2}
    local args=("${@:3}" --write-out '%{http_code}' --silent --output /dev/null)
    status_code=$(curl --max-time ${TIMEOUT_SECS} "${args[@]}" "${url}")
    if [[ "${status_code}" -ne ${status} ]] ; then
      echo "[Fail] Unexpected response with code ${status_code} from ${url}, expected ${status}"
      exit 1
    fi
    echo "[Ok] Got status code ${status_code}, expected ${status}"
}

# check_body sends the given HTTP request and checks the response body.
# $1: The URL to send requests to.
# $2: true/false indicating if an empty, or null body is expected or not.
# $3-N: The rest of the arguments will be passed to the curl command as additional arguments
#       to customize the HTTP call.
function check_body() {
    local url=${1}
    local empty=${2}
    local args=("${@:3}" --silent)
    response_body=$(curl --max-time ${TIMEOUT_SECS} "${args[@]}" "${url}")
    if [[ "${empty}" == "true" ]] && [[ -n "${response_body}" ]]; then
      echo -e "[Fail] Unexpected response with a body. Body dump:\n${response_body}"
      exit 1
    fi
    if [[ "${empty}" != "true" ]] && [[ -z "${response_body}" ]]; then
      echo -e "[Fail] Unexpected response with a body. Body dump:\n${response_body}"
      exit 1
    fi
    echo "[Ok] Got response with an expected body (empty=${empty})"
}

step=1
total_steps=12

## Testing that basic coraza phases are working

# Testing if the server is up
echo "[${step}/${total_steps}] Testing application reachability"
wait_for_service "${health_url}" 15

# Testing envoy container reachability with an unfiltered GET request
((step+=1))
echo "[${step}/${total_steps}] (onRequestheaders) Testing true negative request"
wait_for_service "${envoy_url_echo}?arg=arg_1" 20

# Testing filtered request
((step+=1))
echo "[${step}/${total_steps}] (onRequestheaders) Testing true positive custom rule"
check_status "${envoy_url_filtered}" 403
# This test ensures the response body is empty on interruption. Specifically this makes
# sure no body is returned although actionContinue is passed in phase 3 & 4.
# See https://github.com/corazawaf/coraza-proxy-wasm/pull/126
check_body "${envoy_url_filtered}" true

# Testing body true negative
((step+=1))
echo "[${step}/${total_steps}] (onRequestBody) Testing true negative request (body)"
check_status "${envoy_url_echo}" 200 -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data "${tueNegativeBodyPayload}"

# Testing body detection
((step+=1))
echo "[${step}/${total_steps}] (onRequestBody) Testing true positive request (body)"
check_status "${envoy_url_unfiltered}" 403 -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data "${truePositiveBodyPayload}"

# Testing response headers detection
((step+=1))
#echo "[${step}/${total_steps}] (onResponseHeaders) Testing true positive"
#check_status "${envoy_url_filtered_resp_header}" 403

# TODO(M4tteoP): Update response body e2e after https://github.com/corazawaf/coraza-proxy-wasm/issues/26
# Testing response body true negative
((step+=1))
echo "[${step}/${total_steps}] (onResponseBody) Testing true negative"
check_body "${envoy_url_unfiltered}" false -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data "${trueNegativeBodyPayloadForResponseBody}"

# Testing response body detection
((step+=1))
echo "[${step}/${total_steps}] (onResponseBody) Testing true positive"
check_body "${envoy_url_echo}" true -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data "${truePositiveBodyPayloadForResponseBody}"

## Testing extra requests examples from the readme and some CRS rules in anomaly score mode.

# Testing XSS detection during phase 1
((step+=1))
echo "[${step}/${total_steps}] Testing XSS detection at request headers"
check_status "${envoy_url_echo}?arg=<script>alert(0)</script>" 403

# Testing SQLI detection during phase 2
((step+=1))
echo "[${step}/${total_steps}] Testing SQLi detection at request body"
check_status "${envoy_url_echo}" 403 -X POST --data "1%27%20ORDER%20BY%203--%2B"

# Triggers a CRS scanner detection rule (913100)
((step+=1))
echo "[${step}/${total_steps}] (onRequestBody) Testing CRS rule 913100"
check_status "${envoy_url_echo}" 403 --user-agent "Grabber/0.1 (X11; U; Linux i686; en-US; rv:1.7)" -H "Host: localhost" -H "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"

# True negative GET request with an usual user-agent
((step+=1))
echo "[${step}/${total_steps}] True negative GET request with user-agent"
check_status "${envoy_url_echo}" 200 --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"

echo "[Done] All tests passed"
