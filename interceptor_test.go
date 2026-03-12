// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
	i.Flush()

	require.True(t, i.isWriteHeaderFlush, "status code should have been flushed")
	require.True(t, rec.Flushed, "underlying http.Flusher should have been called")
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
	tx.ProcessRequestBody()

	wrapped, processResponse := wrap(rec, r, tx)

	wrapped.Header().Set("Content-Type", "text/plain")
	wrapped.WriteHeader(http.StatusOK)
	wrapped.Write([]byte("blocked-content"))

	err := processResponse(tx, r)
	// The rule should have triggered and returned an error
	require.Error(t, err, "response body rule should still trigger for non-WebSocket requests")
}
