// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"net/http"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/require"
)

func TestHTTP(t *testing.T) {
	cfg := coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "456" "id:1,phase:2,deny,status:403"
	`)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	// we build a sample POST request
	r, err := http.NewRequest("POST", "/sample.php", strings.NewReader("test=456"))
	if err != nil {
		t.Error(err)
	}
	r.Header.Add("Content-Type", "x-www-form-urlencoded")
	it, err := processRequest(tx, r)
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("transaction should be interrupted")
	}
}

func TestProcessRequestWithTransferEncoding(t *testing.T) {
	cfg := coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Transfer-Encoding "chunked" "id:100,phase:1,deny,status:403"
	`)
	waf, err := coraza.NewWAF(cfg)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	defer tx.Close()

	r, err := http.NewRequest("POST", "/test", strings.NewReader("test body"))
	require.NoError(t, err)
	r.TransferEncoding = []string{"chunked"}

	it, err := processRequest(tx, r)
	require.NoError(t, err)
	require.NotNil(t, it, "expected interruption from Transfer-Encoding rule")
	require.Equal(t, 403, it.Status)
}

func TestParseServerName(t *testing.T) {
	require.Equal(t, "www.example.com", parseServerName("www.example.com"))
	require.Equal(t, "1.2.3.4", parseServerName("1.2.3.4:80"))
	require.Equal(t, "::1", parseServerName("[::1]:8080"))
	require.Equal(t, "[::1]", parseServerName("[::1]"))
	require.Equal(t, "", parseServerName(""))
}

func TestProcessRequestEdgeCases(t *testing.T) {
	newWAFWithBodyAccess := func(t *testing.T) coraza.WAF {
		t.Helper()
		cfg := coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRequestBodyAccess On
`)
		waf, err := coraza.NewWAF(cfg)
		require.NoError(t, err)
		return waf
	}

	t.Run("nil body with body access", func(t *testing.T) {
		waf := newWAFWithBodyAccess(t)
		tx := waf.NewTransaction()
		defer tx.Close()

		req, err := http.NewRequest("POST", "/test", nil)
		require.NoError(t, err)
		req.Host = "example.com"

		it, err := processRequest(tx, req)
		require.NoError(t, err)
		require.Nil(t, it)
	})

	t.Run("http.NoBody with body access", func(t *testing.T) {
		waf := newWAFWithBodyAccess(t)
		tx := waf.NewTransaction()
		defer tx.Close()

		req, err := http.NewRequest("POST", "/test", http.NoBody)
		require.NoError(t, err)
		req.Host = "example.com"

		it, err := processRequest(tx, req)
		require.NoError(t, err)
		require.Nil(t, it)
	})

	t.Run("empty Host", func(t *testing.T) {
		waf := newWAFWithBodyAccess(t)
		tx := waf.NewTransaction()
		defer tx.Close()

		req, err := http.NewRequest("GET", "/test", nil)
		require.NoError(t, err)
		req.Host = ""

		it, err := processRequest(tx, req)
		require.NoError(t, err)
		require.Nil(t, it)
	})

	t.Run("IPv6 host with port", func(t *testing.T) {
		waf := newWAFWithBodyAccess(t)
		tx := waf.NewTransaction()
		defer tx.Close()

		req, err := http.NewRequest("GET", "/test", nil)
		require.NoError(t, err)
		req.Host = "[::1]:8080"

		it, err := processRequest(tx, req)
		require.NoError(t, err)
		require.Nil(t, it)
	})

	t.Run("multiple values for same header", func(t *testing.T) {
		waf := newWAFWithBodyAccess(t)
		tx := waf.NewTransaction()
		defer tx.Close()

		req, err := http.NewRequest("GET", "/test", nil)
		require.NoError(t, err)
		req.Host = "example.com"
		req.Header.Add("X-Multi", "a")
		req.Header.Add("X-Multi", "b")

		it, err := processRequest(tx, req)
		require.NoError(t, err)
		require.Nil(t, it)
	})

	t.Run("HTTP/1.0 protocol", func(t *testing.T) {
		waf := newWAFWithBodyAccess(t)
		tx := waf.NewTransaction()
		defer tx.Close()

		req, err := http.NewRequest("GET", "/test", nil)
		require.NoError(t, err)
		req.Proto = "HTTP/1.0"
		req.Host = "example.com"

		it, err := processRequest(tx, req)
		require.NoError(t, err)
		require.Nil(t, it)
	})

	t.Run("GET with no body and body access on", func(t *testing.T) {
		waf := newWAFWithBodyAccess(t)
		tx := waf.NewTransaction()
		defer tx.Close()

		req, err := http.NewRequest("GET", "/test", nil)
		require.NoError(t, err)
		req.Host = "example.com"

		it, err := processRequest(tx, req)
		require.NoError(t, err)
		require.Nil(t, it)
	})
}
