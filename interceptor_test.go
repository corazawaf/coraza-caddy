// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// TestConcurrentFlushDoesNotBlock verifies that calling Flush() on many
// concurrent streams does not block, even when response body buffering is
// enabled (the early-return path) or disabled (the real-flush path).
// A barrier ensures all streams are open at the same time before any of
// them starts flushing.
func TestConcurrentFlushDoesNotBlock(t *testing.T) {
	const streams = 100

	t.Run("buffered response body (early-return path)", func(t *testing.T) {
		// WAF with response body inspection enabled — Flush() should
		// early-return while the body is still being buffered.
		waf := newWAF(t, `
			SecRuleEngine On
			SecResponseBodyAccess On
			SecResponseBodyMimeType text/plain
		`)

		testConcurrentFlush(t, waf, streams, "text/plain")
	})

	t.Run("non-buffered response body (real-flush path)", func(t *testing.T) {
		// WAF with response body inspection disabled — Flush() should
		// delegate to the underlying writer's Flush().
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
