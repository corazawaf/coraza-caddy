// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// unwrapOnlyResponseWriter mimics caddy's ResponseWriterWrapper: it exposes
// neither Flush nor Hijack itself, only the writer behind Unwrap does.
type unwrapOnlyResponseWriter struct{ inner http.ResponseWriter }

func (w unwrapOnlyResponseWriter) Header() http.Header         { return w.inner.Header() }
func (w unwrapOnlyResponseWriter) Write(b []byte) (int, error) { return w.inner.Write(b) }
func (w unwrapOnlyResponseWriter) WriteHeader(statusCode int)  { w.inner.WriteHeader(statusCode) }
func (w unwrapOnlyResponseWriter) Unwrap() http.ResponseWriter { return w.inner }

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
		{"hijacker behind unwrap", unwrapOnlyResponseWriter{hijackerResponseWriter{rec}}, true, false},
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

// TestConcurrentFlushDoesNotBlock verifies that calling Flush() on many
// concurrent streams does not block, even when response body buffering is
// enabled (the early-return path) or disabled (the real-flush path).
// A barrier ensures all streams are open at the same time before any of
// them starts flushing.
func TestConcurrentFlushDoesNotBlock(t *testing.T) {
	const streams = 100

	t.Run("buffered response body (early-return path)", func(t *testing.T) {
		waf := newWAF(t, `
			SecRuleEngine On
			SecResponseBodyAccess On
			SecResponseBodyMimeType text/plain
		`)

		testConcurrentFlush(t, waf, streams, "text/plain")
	})

	t.Run("non-buffered response body (real-flush path)", func(t *testing.T) {
		waf := newWAF(t, `
			SecRuleEngine On
			SecResponseBodyAccess Off
		`)

		testConcurrentFlush(t, waf, streams, "application/octet-stream")
	})
}

func newWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	cfg := coraza.NewWAFConfig().WithDirectives(directives)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("creating WAF: %v", err)
	}
	return waf
}

// streamState holds a single stream's pre-built state so that it can be
// kept open while all other streams are being set up.
type streamState struct {
	tx                types.Transaction
	rec               *httptest.ResponseRecorder
	req               *http.Request
	wrappedWriter     http.ResponseWriter
	flusher           http.Flusher
	responseProcessor func(types.Transaction, *http.Request) error
}

func testConcurrentFlush(t *testing.T, waf coraza.WAF, streams int, contentType string) {
	t.Helper()

	// Phase 1 — open all streams (write the first chunk to each).
	states := make([]streamState, streams)
	for i := 0; i < streams; i++ {
		tx := waf.NewTransaction()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		wrappedWriter, responseProcessor := wrap(rec, req, tx)
		wrappedWriter.Header().Set("Content-Type", contentType)

		flusher, ok := wrappedWriter.(http.Flusher)
		if !ok {
			tx.Close()
			t.Fatal("wrapped writer does not implement http.Flusher")
		}

		// Write the first chunk so the stream is actively open.
		if _, err := wrappedWriter.Write([]byte("chunk-1 ")); err != nil {
			tx.Close()
			t.Fatalf("stream %d: initial Write: %v", i, err)
		}

		states[i] = streamState{
			tx:                tx,
			rec:               rec,
			req:               req,
			wrappedWriter:     wrappedWriter,
			flusher:           flusher,
			responseProcessor: responseProcessor,
		}
	}

	// Phase 2 — all streams are open; now flush them all concurrently.
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(streams)
		for i := range states {
			go func(s *streamState) {
				defer wg.Done()
				finishStream(t, s)
			}(&states[i])
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All streams completed without blocking.
	case <-time.After(10 * time.Second):
		t.Fatal("timed out: concurrent Flush() calls appear to be blocking")
	}
}

// finishStream flushes, writes the remaining chunks, runs the response
// processor, and validates the final body.
func finishStream(t *testing.T, s *streamState) {
	t.Helper()
	defer func() { _ = s.tx.Close() }()

	// Flush with all streams still open.
	s.flusher.Flush()

	// Write remaining chunks with interleaved flushes.
	remaining := []string{"chunk-2 ", "chunk-3"}
	for _, chunk := range remaining {
		if _, err := s.wrappedWriter.Write([]byte(chunk)); err != nil {
			t.Errorf("Write: %v", err)
			return
		}
		s.flusher.Flush()
	}

	if err := s.responseProcessor(s.tx, s.req); err != nil {
		t.Errorf("responseProcessor: %v", err)
		return
	}

	body := s.rec.Body.String()
	expected := "chunk-1 chunk-2 chunk-3"
	if body != expected {
		t.Errorf("body mismatch: got %q, want %q", body, expected)
	}
}

func TestWriteWhenInterrupted(t *testing.T) {
	waf := newWAF(t, `
		SecRuleEngine On
		SecRule REQUEST_URI "/blocked" "id:1,phase:1,deny,status:403"
	`)
	tx := waf.NewTransaction()
	defer tx.Close()

	// Trigger phase-1 interruption via request headers
	req, _ := http.NewRequest("GET", "/blocked", nil)
	req.Host = "example.com"
	it, err := processRequest(tx, req)
	require.NoError(t, err)
	require.NotNil(t, it, "expected phase-1 interruption")

	rec := httptest.NewRecorder()
	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}

	data := []byte("this should not be written")
	n, writeErr := i.Write(data)
	require.NoError(t, writeErr)
	require.Equal(t, len(data), n)
	require.Empty(t, rec.Body.String(), "no data should reach the underlying writer")
}

func TestFlushDelegatesToUnderlyingFlusher(t *testing.T) {
	waf := newWAF(t, `
		SecRuleEngine On
		SecResponseBodyAccess Off
	`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := httptest.NewRecorder()
	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}

	i.WriteHeader(http.StatusOK)
	// Write triggers flushWriteHeader for the non-buffered path
	_, _ = i.Write([]byte("data"))
	i.Flush()

	require.True(t, i.isWriteHeaderFlush, "status code should have been flushed")
	require.True(t, rec.Flushed, "underlying http.Flusher should have been called")
}

func TestFlushDelegatesThroughUnwrap(t *testing.T) {
	waf := newWAF(t, `
		SecRuleEngine On
		SecResponseBodyAccess Off
	`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := httptest.NewRecorder()
	i := &rwInterceptor{w: unwrapOnlyResponseWriter{rec}, tx: tx, proto: "HTTP/1.1", statusCode: 200}

	i.WriteHeader(http.StatusOK)
	// Write triggers flushWriteHeader for the non-buffered path
	_, _ = i.Write([]byte("data"))
	i.Flush()

	require.True(t, rec.Flushed, "flusher behind Unwrap should have been called")
}

// TestConcurrentStreamingResponseFlush uses real HTTP connections to verify
// that 100 concurrent streaming responses flushed through the interceptor
// deliver chunks to clients without blocking each other.
// Only the non-buffered path is tested here because when response body
// inspection is enabled, the WAF intentionally holds all data until
// processing completes — streaming does not apply in that case.
func TestConcurrentStreamingResponseFlush(t *testing.T) {
	const streams = 100
	const numChunks = 3

	waf := newWAF(t, `
		SecRuleEngine On
		SecResponseBodyAccess Off
	`)

	testStreamingFlush(t, waf, streams, numChunks, "text/event-stream")
}

func testStreamingFlush(t *testing.T, waf coraza.WAF, streams, numChunks int, contentType string) {
	t.Helper()

	// Each handler goroutine blocks on its gate channel, so we can
	// ensure all streams are open before any of them starts writing.
	type gate struct {
		write chan struct{} // closed to tell the handler to start writing chunks
		done  chan struct{} // closed when the handler has finished
	}
	gates := make([]gate, streams)
	for i := range gates {
		gates[i] = gate{
			write: make(chan struct{}),
			done:  make(chan struct{}),
		}
	}

	var handlerIdx int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		idx := handlerIdx
		handlerIdx++
		mu.Unlock()

		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()

		wrappedWriter, responseProcessor := wrap(w, r, tx)
		wrappedWriter.Header().Set("Content-Type", contentType)

		flusher, ok := wrappedWriter.(http.Flusher)
		if !ok {
			http.Error(wrappedWriter, "flusher not available", http.StatusInternalServerError)
			close(gates[idx].done)
			return
		}

		// Signal that this stream is open and wait for the go-ahead.
		// The first Write+Flush ensures the response headers are sent
		// and the client can see the connection is alive.
		if _, err := wrappedWriter.Write([]byte("chunk-0\n")); err != nil {
			t.Errorf("stream %d: initial write: %v", idx, err)
			close(gates[idx].done)
			return
		}
		flusher.Flush()

		// Wait until all streams are open before writing the rest.
		<-gates[idx].write

		for c := 1; c <= numChunks; c++ {
			if _, err := fmt.Fprintf(wrappedWriter, "chunk-%d\n", c); err != nil {
				t.Errorf("stream %d: write chunk %d: %v", idx, c, err)
				close(gates[idx].done)
				return
			}
			flusher.Flush()
		}

		if err := responseProcessor(tx, r); err != nil {
			t.Errorf("stream %d: responseProcessor: %v", idx, err)
		}
		close(gates[idx].done)
	}))
	defer server.Close()

	// Phase 1: open all streams concurrently and read the initial chunk
	// from each to confirm the connection is established and streaming.
	type clientStream struct {
		resp   *http.Response
		reader *bufio.Reader
	}
	clients := make([]clientStream, streams)
	var openWg sync.WaitGroup
	openWg.Add(streams)

	for i := 0; i < streams; i++ {
		go func(idx int) {
			defer openWg.Done()
			resp, err := http.Get(server.URL)
			if err != nil {
				t.Errorf("stream %d: GET: %v", idx, err)
				return
			}
			reader := bufio.NewReader(resp.Body)
			// Read the initial chunk to confirm the stream is alive.
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Errorf("stream %d: reading initial chunk: %v", idx, err)
				resp.Body.Close()
				return
			}
			if line != "chunk-0\n" {
				t.Errorf("stream %d: initial chunk: got %q, want %q", idx, line, "chunk-0\n")
			}
			clients[idx] = clientStream{resp: resp, reader: reader}
		}(i)
	}

	openDone := make(chan struct{})
	go func() { openWg.Wait(); close(openDone) }()
	select {
	case <-openDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for all streams to open")
	}

	// Phase 2: all streams confirmed open — release all handlers at once.
	for i := range gates {
		close(gates[i].write)
	}

	// Phase 3: read remaining chunks from all streams concurrently.
	readDone := make(chan struct{})
	go func() {
		var readWg sync.WaitGroup
		readWg.Add(streams)
		for i := 0; i < streams; i++ {
			go func(idx int) {
				defer readWg.Done()
				cs := clients[idx]
				if cs.resp == nil {
					return
				}
				defer cs.resp.Body.Close()

				for c := 1; c <= numChunks; c++ {
					line, err := cs.reader.ReadString('\n')
					if err != nil && err != io.EOF {
						t.Errorf("stream %d: reading chunk %d: %v", idx, c, err)
						return
					}
					expected := fmt.Sprintf("chunk-%d\n", c)
					if line != expected {
						t.Errorf("stream %d chunk %d: got %q, want %q", idx, c, line, expected)
					}
				}
			}(i)
		}
		readWg.Wait()
		close(readDone)
	}()

	select {
	case <-readDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out reading streamed chunks — streams appear to be blocking")
	}

	// Wait for all handlers to finish.
	for i := range gates {
		<-gates[i].done
	}
}

// writeHeaderTracker wraps httptest.ResponseRecorder and records whether
// WriteHeader was actually called on the underlying writer.
type writeHeaderTracker struct {
	*httptest.ResponseRecorder
	writeHeaderCalled bool
}

func (w *writeHeaderTracker) WriteHeader(code int) {
	w.writeHeaderCalled = true
	w.ResponseRecorder.WriteHeader(code)
}

func newWriteHeaderTracker() *writeHeaderTracker {
	return &writeHeaderTracker{ResponseRecorder: httptest.NewRecorder()}
}

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

func TestWrapPreservesHijackerInterface(t *testing.T) {
	waf := newWAF(t, `SecRuleEngine On`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, _ := wrap(rec, r, tx)

	_, ok := wrapped.(http.Hijacker)
	require.True(t, ok, "wrapped writer should implement http.Hijacker")
}

func TestWrapWithoutHijacker(t *testing.T) {
	waf := newWAF(t, `SecRuleEngine On`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)

	wrapped, _ := wrap(rec, r, tx)

	_, ok := wrapped.(http.Hijacker)
	require.False(t, ok, "wrapped writer should not implement http.Hijacker when underlying writer doesn't")
}

func TestWebSocketUpgradeFlushesHeaders(t *testing.T) {
	waf := newWAF(t, `SecRuleEngine On`)
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
	waf := newWAF(t, `
		SecRuleEngine On
		SecResponseBodyAccess On
		SecResponseBodyMimeType text/plain
	`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newWriteHeaderTracker()
	r, _ := http.NewRequest("GET", "/", nil)

	wrapped, _ := wrap(rec, r, tx)

	wrapped.Header().Set("Content-Type", "text/plain")
	wrapped.WriteHeader(http.StatusOK)

	// For normal responses with body access, the status should NOT be flushed yet
	// (it's deferred until body processing is done). We verify by checking that
	// WriteHeader was never called on the underlying writer.
	require.False(t, rec.writeHeaderCalled,
		"underlying WriteHeader should not be called immediately for non-WebSocket responses")
}

func TestHijackTrackerSetsIsHijacked(t *testing.T) {
	waf := newWAF(t, `SecRuleEngine On`)
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
	waf := newWAF(t, `
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
	waf := newWAF(t, `SecRuleEngine DetectionOnly`)
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

// failingHijacker simulates a Hijack() that fails.
type failingHijacker struct {
	*httptest.ResponseRecorder
}

func (f *failingHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, fmt.Errorf("hijack not supported")
}

func TestHijackFailureDoesNotSkipResponseProcessing(t *testing.T) {
	waf := newWAF(t, `SecRuleEngine On`)
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := &failingHijacker{ResponseRecorder: httptest.NewRecorder()}
	r, _ := http.NewRequest("GET", "/", nil)

	wrapped, processResponse := wrap(rec, r, tx)

	hijacker, ok := wrapped.(http.Hijacker)
	require.True(t, ok, "should implement http.Hijacker")

	_, _, err := hijacker.Hijack()
	require.Error(t, err, "Hijack should fail")

	// processResponse should still work since hijack failed
	err = processResponse(tx, r)
	require.NoError(t, err, "processResponse should still run when Hijack fails")
}

func TestRegularRequestStillProcessesResponseBody(t *testing.T) {
	waf := newWAF(t, `
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
	_, err := tx.ProcessRequestBody()
	require.NoError(t, err)

	wrapped, processResponse := wrap(rec, r, tx)

	wrapped.Header().Set("Content-Type", "text/plain")
	wrapped.WriteHeader(http.StatusOK)
	_, err = wrapped.Write([]byte("blocked-content"))
	require.NoError(t, err)

	err = processResponse(tx, r)
	// The rule should have triggered and returned an error
	require.Error(t, err, "response body rule should still trigger for non-WebSocket requests")
}

// hintedResponse is what a client saw of a response that began with an
// informational (1xx) response.
type hintedResponse struct {
	hint    textproto.MIMEHeader // the first 103, nil if none arrived
	held    bool                 // the handler gave up waiting for the 103
	status  int
	header  http.Header
	body    string
	procErr error
}

// serveWithEarlyHints serves one response through the interceptor. serve
// writes to the intercepted writer and calls awaitHint where the client
// must already have received the 103: it blocks until the client has it, so
// the test does not depend on timing, and it records held if the 103 never
// arrives within ctx.
func serveWithEarlyHints(t *testing.T, tx types.Transaction, serve func(ww http.ResponseWriter, awaitHint func())) hintedResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	hints := make(chan textproto.MIMEHeader, 4)
	hinted := make(chan struct{})
	var once sync.Once
	var held atomic.Bool
	procErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww, processResponse := wrap(w, r, tx)
		serve(ww, func() {
			select {
			case <-hinted:
			case <-ctx.Done():
				held.Store(true)
			}
		})
		procErr <- processResponse(tx, r)
	}))
	defer srv.Close()

	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints {
			hints <- h
			once.Do(func() { close(hinted) })
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	out := hintedResponse{status: resp.StatusCode, header: resp.Header, body: string(body)}
	select {
	case out.procErr = <-procErr:
	case <-ctx.Done():
		t.Fatal("the handler did not finish in time")
	}
	select {
	case out.hint = <-hints:
	default:
	}
	out.held = held.Load()
	return out
}

// An informational response is passed straight to the client, and the
// final status that follows it is kept.
func TestEarlyHintsKeepTheFinalStatus(t *testing.T) {
	for _, final := range []int{
		http.StatusOK,
		http.StatusFound,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusInternalServerError,
	} {
		t.Run(http.StatusText(final), func(t *testing.T) {
			tx := newTestTransaction(t)
			defer tx.Close()
			got := serveWithEarlyHints(t, tx, func(ww http.ResponseWriter, awaitHint func()) {
				ww.Header().Set("Link", "</style.css>; rel=preload; as=style")
				ww.WriteHeader(http.StatusEarlyHints)
				awaitHint()
				ww.WriteHeader(final)
				_, _ = ww.Write([]byte("body"))
			})
			require.False(t, got.held, "the 103 was held until the final response")
			require.NotNil(t, got.hint, "the 103 never reached the client")
			require.NoError(t, got.procErr)
			require.Equal(t, final, got.status, "a %d sent after Early Hints reached the client as %d", final, got.status)
		})
	}
}

// The response headers phase has not seen the headers when a 103 is sent,
// so only Link goes out with it. The rest still go with the final response.
func TestEarlyHintsOnlySendLink(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()
	got := serveWithEarlyHints(t, tx, func(ww http.ResponseWriter, awaitHint func()) {
		ww.Header().Set("Link", "</style.css>; rel=preload; as=style")
		ww.Header().Set("Set-Cookie", "session=secret")
		ww.Header().Set("X-Debug", "internal")
		ww.WriteHeader(http.StatusEarlyHints)
		awaitHint()
		ww.WriteHeader(http.StatusOK)
		_, _ = ww.Write([]byte("body"))
	})
	require.False(t, got.held)
	require.NotNil(t, got.hint, "the 103 never reached the client")
	require.Equal(t, []string{"</style.css>; rel=preload; as=style"}, got.hint["Link"])
	require.Len(t, got.hint, 1, "the 103 carried more than Link: %v", got.hint)
	require.Equal(t, "session=secret", got.header.Get("Set-Cookie"))
	require.Equal(t, "internal", got.header.Get("X-Debug"))
}

// The response rules judge the final status, never a 1xx.
func TestEarlyHintsStatusSeenByTheResponseRules(t *testing.T) {
	const bodyAccess = "SecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\n"
	tests := map[string]struct {
		directives string
		final      int
		wantStatus int
		wantBody   string
	}{
		"a rule on 103 never fires": {
			directives: `SecRule RESPONSE_STATUS "@streq 103" "id:1,phase:3,deny,status:500"`,
			final:      http.StatusOK,
			wantStatus: http.StatusOK,
			wantBody:   "ok",
		},
		"a rule on the final status fires": {
			directives: `SecRule RESPONSE_STATUS "@streq 404" "id:1,phase:3,deny,status:418"`,
			final:      http.StatusNotFound,
			wantStatus: http.StatusTeapot,
		},
		"final status held for the body, rule on 103 never fires": {
			directives: bodyAccess + `SecRule RESPONSE_STATUS "@streq 103" "id:1,phase:3,deny,status:500"`,
			final:      http.StatusOK,
			wantStatus: http.StatusOK,
			wantBody:   "ok",
		},
		"final status held for the body, rule on it fires": {
			directives: bodyAccess + `SecRule RESPONSE_STATUS "@streq 404" "id:1,phase:3,deny,status:418"`,
			final:      http.StatusNotFound,
			wantStatus: http.StatusTeapot,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tx := newWAF(t, "SecRuleEngine On\n"+tc.directives).NewTransaction()
			defer tx.Close()
			got := serveWithEarlyHints(t, tx, func(ww http.ResponseWriter, awaitHint func()) {
				ww.Header().Set("Link", "</style.css>; rel=preload; as=style")
				ww.Header().Set("Content-Type", "text/plain")
				ww.WriteHeader(http.StatusEarlyHints)
				awaitHint()
				ww.WriteHeader(tc.final)
				_, _ = ww.Write([]byte("ok"))
			})
			require.False(t, got.held)
			require.NoError(t, got.procErr)
			require.Equal(t, tc.wantStatus, got.status)
			require.Equal(t, tc.wantBody, got.body)
		})
	}
}

// statusLog records every status code that reaches the delegate writer.
type statusLog struct {
	http.ResponseWriter
	codes []int
}

func (s *statusLog) WriteHeader(code int) {
	s.codes = append(s.codes, code)
	s.ResponseWriter.WriteHeader(code)
}

// Once the transaction is interrupted nothing more reaches the client: not a
// late 1xx, and not a Flush that writes the headers a second time.
func TestNothingReachesTheClientAfterAnInterruption(t *testing.T) {
	waf := newWAF(t, `SecRuleEngine On
SecRule RESPONSE_STATUS "@streq 404" "id:1,phase:3,deny,status:418"`)
	tx := waf.NewTransaction()
	defer tx.Close()

	log := &statusLog{ResponseWriter: httptest.NewRecorder()}
	i := &rwInterceptor{w: log, tx: tx, proto: "HTTP/1.1", statusCode: 200}

	i.WriteHeader(http.StatusNotFound)
	require.True(t, tx.IsInterrupted())
	require.Equal(t, []int{http.StatusTeapot}, log.codes)
	// set even though the response was interrupted, so that nothing after
	// this runs the response headers phase again
	require.True(t, i.wroteHeader)

	i.WriteHeader(http.StatusEarlyHints)
	i.Flush()
	require.Equal(t, []int{http.StatusTeapot}, log.codes)
}

// A 1xx is not sent when the transaction was interrupted before the response
// began (here at the request headers phase), nor once the final status has
// been flushed.
func TestEarlyHintsNotSentWhenNothingMayBeSent(t *testing.T) {
	t.Run("interrupted before the response", func(t *testing.T) {
		waf := newWAF(t, `SecRuleEngine On
SecRule REQUEST_URI "@rx ." "id:2,phase:1,deny,status:403"`)
		tx := waf.NewTransaction()
		defer tx.Close()
		tx.ProcessURI("/", http.MethodGet, "HTTP/1.1")
		require.NotNil(t, tx.ProcessRequestHeaders())

		log := &statusLog{ResponseWriter: httptest.NewRecorder()}
		i := &rwInterceptor{w: log, tx: tx, proto: "HTTP/1.1", statusCode: 200}
		i.WriteHeader(http.StatusEarlyHints)
		require.Empty(t, log.codes)
	})
	t.Run("final status already flushed", func(t *testing.T) {
		tx := newTestTransaction(t)
		defer tx.Close()

		log := &statusLog{ResponseWriter: httptest.NewRecorder()}
		i := &rwInterceptor{w: log, tx: tx, proto: "HTTP/1.1", statusCode: 200, isWriteHeaderFlush: true}
		i.WriteHeader(http.StatusEarlyHints)
		require.Empty(t, log.codes)
	})
}

// A Flush between a 1xx and the final status commits a 200, as net/http does
// for a Flush before any WriteHeader. A handler that wants another status
// sets it before it flushes.
func TestFlushAfterEarlyHintsCommitsOK(t *testing.T) {
	tx := newTestTransaction(t)
	defer tx.Close()
	got := serveWithEarlyHints(t, tx, func(ww http.ResponseWriter, awaitHint func()) {
		ww.Header().Set("Link", "</style.css>; rel=preload; as=style")
		ww.WriteHeader(http.StatusEarlyHints)
		awaitHint()
		ww.(http.Flusher).Flush()
		ww.WriteHeader(http.StatusForbidden)
	})
	require.False(t, got.held)
	require.Equal(t, http.StatusOK, got.status)
}
