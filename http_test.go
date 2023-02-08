// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
