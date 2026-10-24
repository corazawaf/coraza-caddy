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

// earlyHintsThroughInterceptor serves one response through the WAF's
// interceptor: a 103, a pause, then final. It returns how long the 103
// took to arrive and the final status the client saw.
func earlyHintsThroughInterceptor(t *testing.T, final int) (time.Duration, int) {
	t.Helper()
	tx := newTestTransaction(t)
	defer tx.Close()
	handlerErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww, processResponse := wrap(w, r, tx)
		ww.Header().Set("Link", "</style.css>; rel=preload; as=style")
		ww.WriteHeader(http.StatusEarlyHints)
		time.Sleep(earlyHintsDelay)
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
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	require.NoError(t, <-handlerErr)
	return hint, resp.StatusCode
}

func TestEarlyHintsPassStraightThrough(t *testing.T) {
	hint, status := earlyHintsThroughInterceptor(t, http.StatusOK)
	require.NotZero(t, hint, "the 103 never reached the client")
	require.Less(t, hint, earlyHintsDelay/2, "the 103 was held until the final response")
	require.Equal(t, http.StatusOK, status)
}

func TestTheFinalStatusAfterEarlyHintsIsKept(t *testing.T) {
	for _, final := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusFound, http.StatusInternalServerError} {
		_, status := earlyHintsThroughInterceptor(t, final)
		require.Equal(t, final, status, "a %d sent after Early Hints reached the client as %d", final, status)
	}
}
