// Copyright 2024 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
)

func newTestTransaction(t *testing.T) types.Transaction {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	require.NoError(t, err)
	return waf.NewTransaction()
}

func TestReadFrom(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()

	rec := httptest.NewRecorder()
	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}

	data := "hello world from ReadFrom"
	n, err := i.ReadFrom(strings.NewReader(data))
	require.NoError(t, err)
	require.Equal(t, int64(len(data)), n)
	require.Equal(t, data, rec.Body.String())
}

func TestFlush(t *testing.T) {
	t.Run("triggers WriteHeader when not yet written", func(t *testing.T) {
		tx := newTestTransaction(t)
		defer tx.Close()

		rec := httptest.NewRecorder()
		i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}

		require.False(t, i.wroteHeader)
		i.Flush()
		require.True(t, i.wroteHeader)
	})

	t.Run("no-op after WriteHeader", func(t *testing.T) {
		tx := newTestTransaction(t)
		defer tx.Close()

		rec := httptest.NewRecorder()
		i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}

		i.WriteHeader(http.StatusCreated)
		i.Flush()
		require.Equal(t, http.StatusCreated, i.statusCode)
	})
}

func TestObtainStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		action     string
		status     int
		defaultSC  int
		wantStatus int
	}{
		{"deny with explicit status", "deny", 503, 200, 503},
		{"deny with zero status defaults to 403", "deny", 0, 200, 403},
		{"non-deny returns default", "redirect", 302, 200, 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			it := &types.Interruption{Action: tt.action, Status: tt.status}
			require.Equal(t, tt.wantStatus, obtainStatusCodeFromInterruptionOrDefault(it, tt.defaultSC))
		})
	}
}

func TestWriteHeaderSuperfluous(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()

	rec := httptest.NewRecorder()
	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}

	i.WriteHeader(http.StatusCreated)
	require.Equal(t, http.StatusCreated, i.statusCode)

	// Second call is a no-op
	i.WriteHeader(http.StatusNotFound)
	require.Equal(t, http.StatusCreated, i.statusCode)
}

func TestWriteTriggersWriteHeader(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()

	rec := httptest.NewRecorder()
	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}

	n, err := i.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.True(t, i.wroteHeader)
}

func TestCleanHeaders(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()

	rec := httptest.NewRecorder()
	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}

	i.Header().Set("X-Test", "value")
	i.Header().Set("X-Other", "other")
	require.NotEmpty(t, rec.Header())

	i.cleanHeaders()
	require.Empty(t, rec.Header())
}

func TestFlushWriteHeader(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()

	rec := httptest.NewRecorder()
	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 201}

	require.False(t, i.isWriteHeaderFlush)
	i.flushWriteHeader()
	require.True(t, i.isWriteHeaderFlush)
	require.Equal(t, 201, rec.Code)

	// Second call is a no-op
	i.flushWriteHeader()
	require.True(t, i.isWriteHeaderFlush)
}

// Mock types for testing wrap interface preservation.

type plainResponseWriter struct{ http.ResponseWriter }

type hijackerResponseWriter struct{ http.ResponseWriter }

func (hijackerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }

type pusherResponseWriter struct{ http.ResponseWriter }

func (pusherResponseWriter) Push(string, *http.PushOptions) error { return nil }

type hijackerPusherResponseWriter struct{ http.ResponseWriter }

func (hijackerPusherResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

func (hijackerPusherResponseWriter) Push(string, *http.PushOptions) error { return nil }

func TestWrapPreservesInterfaces(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	tests := []struct {
		name       string
		rw         http.ResponseWriter
		wantHijack bool
		wantPush   bool
	}{
		{"plain writer", plainResponseWriter{rec}, false, false},
		{"hijacker writer", hijackerResponseWriter{rec}, true, false},
		{"pusher writer", pusherResponseWriter{rec}, false, true},
		{"hijacker+pusher writer", hijackerPusherResponseWriter{rec}, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := newTestTransaction(t)
			defer tx.Close()

			wrapped, processResp := wrap(tt.rw, req, tx)
			require.NotNil(t, processResp)

			_, isHijacker := wrapped.(http.Hijacker)
			require.Equal(t, tt.wantHijack, isHijacker)

			_, isPusher := wrapped.(http.Pusher)
			require.Equal(t, tt.wantPush, isPusher)

			// All wrapped writers should implement Flusher
			_, isFlusher := wrapped.(http.Flusher)
			require.True(t, isFlusher)
		})
	}
}

func TestResponseProcessor(t *testing.T) {
	t.Run("body not accessible flushes header", func(t *testing.T) {
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On"))
		require.NoError(t, err)
		tx := waf.NewTransaction()
		defer tx.Close()

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)

		_, processResp := wrap(rec, req, tx)
		require.NoError(t, processResp(tx, req))
	})

	t.Run("body accessible writes buffered body", func(t *testing.T) {
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
`))
		require.NoError(t, err)
		tx := waf.NewTransaction()
		defer tx.Close()

		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)

		ww, processResp := wrap(rec, req, tx)
		ww.Header().Set("Content-Type", "text/plain")
		ww.WriteHeader(http.StatusOK)
		_, err = ww.Write([]byte("safe content"))
		require.NoError(t, err)

		require.NoError(t, processResp(tx, req))
	})
}
