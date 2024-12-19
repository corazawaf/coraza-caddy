// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())
var mu sync.Mutex

// RandomString returns a pseudorandom string of length n.
// It is safe to use this function in concurrent environments.
// Implementation from https://stackoverflow.com/a/31832326
// This is taken from Coraza code as a workaround for ID
func randomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)

	mu.Lock()
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	mu.Unlock()

	return sb.String()
}

func getClientAddress(req *http.Request) (string, int) {

	var (
		clientIp   string
		clientPort int
	)

	if address, ok := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey).(string); ok && len(address) > 0 {
		ip, port, _ := net.SplitHostPort(address)
		if ip != "" {
			clientIp = ip
		} else {
			clientIp = address
		}
		clientPort, _ = strconv.Atoi(port)
	} else {
		idx := strings.LastIndexByte(req.RemoteAddr, ':')
		if idx != -1 {
			clientIp = req.RemoteAddr[:idx]
			clientPort, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
		} else {
			clientIp = req.RemoteAddr
			clientPort = 0
		}
	}

	return clientIp, clientPort

}
