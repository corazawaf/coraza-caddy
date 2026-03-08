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
}
