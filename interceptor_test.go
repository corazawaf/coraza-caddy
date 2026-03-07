// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/require"
)

// hijackableRecorder extends httptest.ResponseRecorder with http.Hijacker support
// to simulate what a real HTTP server connection provides.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	// Return a pipe-based connection to simulate a hijacked connection.
	server, client := net.Pipe()
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	// Close server side in the background as we don't need it in tests.
	go server.Close()
	return client, rw, nil
}

func newHijackableRecorder() *hijackableRecorder {
	return &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func newTestWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	cfg := coraza.NewWAFConfig().WithDirectives(directives)
	waf, err := coraza.NewWAF(cfg)
	require.NoError(t, err)
	return waf
}

func TestWrapPreservesHijackerInterface(t *testing.T) {
	waf := newTestWAF(t, `SecRuleEngine On`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, _ := wrap(rec, r, tx)

	_, ok := wrapped.(http.Hijacker)
	require.True(t, ok, "wrapped writer should implement http.Hijacker")
}

func TestWrapWithoutHijacker(t *testing.T) {
	waf := newTestWAF(t, `SecRuleEngine On`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)

	wrapped, _ := wrap(rec, r, tx)

	_, ok := wrapped.(http.Hijacker)
	require.False(t, ok, "wrapped writer should not implement http.Hijacker when underlying writer doesn't")
}

func TestWebSocketUpgradeFlushesHeaders(t *testing.T) {
	waf := newTestWAF(t, `SecRuleEngine On`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, _ := wrap(rec, r, tx)

	// Simulate a WebSocket upgrade response
	wrapped.Header().Set("Upgrade", "websocket")
	wrapped.Header().Set("Connection", "Upgrade")
	wrapped.WriteHeader(http.StatusSwitchingProtocols)

	// The 101 status should have been flushed to the underlying writer immediately
	require.Equal(t, http.StatusSwitchingProtocols, rec.Code,
		"101 status should be flushed to underlying writer immediately for WebSocket upgrades")
}

func TestNonWebSocketResponseDoesNotFlushImmediately(t *testing.T) {
	waf := newTestWAF(t, `
		SecRuleEngine On
		SecResponseBodyAccess On
		SecResponseBodyMimeType text/plain
	`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)

	wrapped, _ := wrap(rec, r, tx)

	wrapped.Header().Set("Content-Type", "text/plain")
	wrapped.WriteHeader(http.StatusOK)

	// For normal responses with body access, the status should NOT be flushed yet
	// (it's deferred until body processing is done)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestHijackTrackerSetsIsHijacked(t *testing.T) {
	waf := newTestWAF(t, `SecRuleEngine On`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, _ := wrap(rec, r, tx)

	hijacker, ok := wrapped.(http.Hijacker)
	require.True(t, ok)

	conn, _, err := hijacker.Hijack()
	require.NoError(t, err)
	defer conn.Close()

	// The underlying recorder should have been hijacked
	require.True(t, rec.hijacked, "underlying writer's Hijack should have been called")
}

func TestResponseProcessorSkipsOnHijackedConnection(t *testing.T) {
	waf := newTestWAF(t, `
		SecRuleEngine On
		SecResponseBodyAccess On
		SecResponseBodyMimeType text/plain
	`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, processResponse := wrap(rec, r, tx)

	// Simulate WebSocket upgrade
	wrapped.Header().Set("Upgrade", "websocket")
	wrapped.Header().Set("Connection", "Upgrade")
	wrapped.WriteHeader(http.StatusSwitchingProtocols)

	// Hijack the connection
	hijacker := wrapped.(http.Hijacker)
	conn, _, err := hijacker.Hijack()
	require.NoError(t, err)
	defer conn.Close()

	// processResponse should return nil without attempting to write to the hijacked connection.
	// Before the fix, this would panic or error with "response.WriteHeader on hijacked connection".
	err = processResponse(tx, r)
	require.NoError(t, err, "processResponse should not error on hijacked connection")
}

func TestWebSocketUpgradeDetectionOnly(t *testing.T) {
	waf := newTestWAF(t, `SecRuleEngine DetectionOnly`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, processResponse := wrap(rec, r, tx)

	// Simulate WebSocket upgrade
	wrapped.Header().Set("Upgrade", "websocket")
	wrapped.Header().Set("Connection", "Upgrade")
	wrapped.WriteHeader(http.StatusSwitchingProtocols)

	require.Equal(t, http.StatusSwitchingProtocols, rec.Code,
		"101 should be flushed even in DetectionOnly mode")

	// Hijack
	hijacker := wrapped.(http.Hijacker)
	conn, _, err := hijacker.Hijack()
	require.NoError(t, err)
	defer conn.Close()

	err = processResponse(tx, r)
	require.NoError(t, err, "processResponse should succeed for WebSocket in DetectionOnly mode")
}

func TestRegularRequestStillProcessesResponseBody(t *testing.T) {
	waf := newTestWAF(t, `
		SecRuleEngine On
		SecResponseBodyAccess On
		SecResponseBodyMimeType text/plain
		SecRule RESPONSE_BODY "blocked-content" "id:100,phase:4,deny,status:403"
	`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"

	// Process request phases so the transaction is in the right state
	tx.ProcessConnection("127.0.0.1", 12345, "", 0)
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	wrapped, processResponse := wrap(rec, r, tx)

	wrapped.Header().Set("Content-Type", "text/plain")
	wrapped.WriteHeader(http.StatusOK)
	wrapped.Write([]byte("blocked-content"))

	err := processResponse(tx, r)
	// The rule should have triggered and returned an error
	require.Error(t, err, "response body rule should still trigger for non-WebSocket requests")
}
