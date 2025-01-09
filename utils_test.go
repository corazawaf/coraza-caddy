// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

func TestParsegClientAddress(t *testing.T) {

	remoteIp := "127.0.0.1"
	remotePort := 9090
	clientIp := "127.0.0.2"
	clientPort := 8080

	req, _ := http.NewRequest("GET", "/", nil)

	req.RemoteAddr = fmt.Sprintf("%v:%v", remoteIp, remotePort)
	ip, port := getClientAddress(req)
	require.Equal(t, remoteIp, ip)
	require.Equal(t, remotePort, port)

	req.RemoteAddr = remoteIp
	ip, port = getClientAddress(req)
	require.Equal(t, remoteIp, ip)
	require.Equal(t, 0, port)

	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, make(map[string]any)))
	req.RemoteAddr = fmt.Sprintf("%v:%v", remoteIp, remotePort)

	ip, port = getClientAddress(req)
	require.Equal(t, remoteIp, ip)
	require.Equal(t, remotePort, port)

	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, fmt.Sprintf("%v:%v", clientIp, clientPort))
	ip, port = getClientAddress(req)
	require.Equal(t, clientIp, ip)
	require.Equal(t, clientPort, port)

	caddyhttp.SetVar(req.Context(), caddyhttp.ClientIPVarKey, clientIp)
	ip, port = getClientAddress(req)
	require.Equal(t, clientIp, ip)
	require.Equal(t, 0, port)
}
