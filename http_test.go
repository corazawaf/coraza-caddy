// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"net/http"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"go.uber.org/zap"
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
	logger, _ := zap.NewDevelopment()
	tx := waf.NewTransaction()
	// we build a sample POST request
	r, err := http.NewRequest("POST", "/sample.php", strings.NewReader("test=456"))
	if err != nil {
		t.Error(err)
	}
	r.Header.Add("Content-Type", "x-www-form-urlencoded")
	it, err := processRequest(tx, r, logger)
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("transaction should be interrupted")
	}
}
