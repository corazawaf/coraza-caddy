// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Regression tests for corazawaf/coraza-caddy#78: WebSocket upgrades must
// survive the interceptor when the underlying writer chain exposes Hijack
// only via Unwrap, as Caddy's own response writer wrappers do (installed
// e.g. when access logging is enabled).

package coraza

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// hijackableRecorder mimics the innermost HTTP/1.1 ResponseWriter: it
// implements http.Hijacker directly.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (r *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	c1, _ := net.Pipe()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

// caddyStyleWrapper mimics caddyhttp.ResponseWriterWrapper: it always has a
// Push method, never a Hijack method, and exposes the inner writer only via
// Unwrap (the http.ResponseController convention).
type caddyStyleWrapper struct {
	http.ResponseWriter
}

func (w caddyStyleWrapper) Push(target string, opts *http.PushOptions) error {
	return http.ErrNotSupported
}

func (w caddyStyleWrapper) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func TestHijackThroughUnwrapOnlyWrapper(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()

	inner := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	outer := caddyStyleWrapper{ResponseWriter: inner}

	// Sanity: the wrapped writer matches the shape seen in production —
	// Pusher via method set, Hijacker reachable only through Unwrap.
	_, isHijacker := interface{}(outer).(http.Hijacker)
	require.False(t, isHijacker)
	_, isPusher := interface{}(outer).(http.Pusher)
	require.True(t, isPusher)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	ww, _ := wrap(outer, req, tx)

	// The reverse proxy hijacks via http.ResponseController, which walks
	// the Unwrap chain. Without Unwrap on the interceptor this fails with
	// http.ErrNotSupported.
	_, _, err := http.NewResponseController(ww).Hijack()
	require.NoError(t, err)
	require.True(t, inner.hijacked)
}

func TestWriteHeader101FlushedImmediately(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	ww, _ := wrap(rec, req, tx)

	// 101 must reach the underlying writer before any hijack happens;
	// buffering it would strand the client waiting for the status line.
	ww.WriteHeader(http.StatusSwitchingProtocols)
	require.Equal(t, http.StatusSwitchingProtocols, rec.Code)
}

func TestWriteHeaderNon101StillBuffered(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ww, _ := wrap(rec, req, tx)

	// Regular statuses keep the existing behaviour: recorded but not yet
	// flushed, so a later phase-4 interruption can still override them.
	ww.WriteHeader(http.StatusTeapot)
	require.Equal(t, http.StatusOK, rec.Code) // recorder default — nothing flushed yet
}
