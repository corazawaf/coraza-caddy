// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const earlyHintsDelay = time.Second

// earlyHintsThroughInterceptor serves one response through the interceptor:
// a 103, a pause, then final. It returns how long the 103 took to arrive and
// the final status the client saw. ctx bounds the request and the pause.
func earlyHintsThroughInterceptor(ctx context.Context, t *testing.T, final int) (time.Duration, int) {
	t.Helper()
	tx := newTestTransaction(t)
	defer tx.Close()
	handlerErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww, processResponse := wrap(w, r, tx)
		ww.Header().Set("Link", "</style.css>; rel=preload; as=style")
		ww.WriteHeader(http.StatusEarlyHints)
		timer := time.NewTimer(earlyHintsDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			handlerErr <- r.Context().Err()
			return
		}
		ww.WriteHeader(final)
		_, _ = ww.Write([]byte("body"))
		handlerErr <- processResponse(tx, r)
	}))
	defer srv.Close()

	start := time.Now()
	var hint time.Duration
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints && hint == 0 {
			hint = time.Since(start)
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	select {
	case err := <-handlerErr:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("the handler did not finish in time")
	}
	return hint, resp.StatusCode
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
			ctx, cancel := context.WithTimeout(context.Background(), 10*earlyHintsDelay)
			defer cancel()
			hint, status := earlyHintsThroughInterceptor(ctx, t, final)
			require.NotZero(t, hint, "the 103 never reached the client")
			require.Less(t, hint, earlyHintsDelay/2, "the 103 was held until the final response")
			require.Equal(t, final, status, "a %d sent after Early Hints reached the client as %d", final, status)
		})
	}
}
