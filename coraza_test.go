// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	corazaWAF "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const baseURL = "http://127.0.0.1:8080"

func TestPlugin(t *testing.T) {
	tester := newTester("test.init.config", t)

	res, _ := tester.AssertGetResponse(baseURL+"/test", 200, "test123")
	// Comes from https://github.com/corazawaf/coraza-caddy/blob/5e8337/test.init.config#L17
	if len(res.Header.Get("x-request-id")) == 0 {
		t.Fatal("X-Request-Id header is not set")
	}
}

func TestPluginReload(t *testing.T) {
	tester := caddytest.NewTester(t)
	configFile := "test.init.config"
	configContent, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)

	rawConfig = strings.ReplaceAll(rawConfig, "test123", "test456")

	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/test", 200, "test456")
}

func TestSimpleRule(t *testing.T) {
	tester := newTester("test.init.config", t)

	req, _ := http.NewRequest("GET", baseURL+"/test5", nil)
	tester.AssertResponseCode(req, 403)

	req, _ = http.NewRequest("GET", baseURL+"/test_include1", nil)
	tester.AssertResponseCode(req, 403)

	req, _ = http.NewRequest("GET", baseURL+"/test_include2", nil)
	tester.AssertResponseCode(req, 403)
}

func TestPhase3Disruption(t *testing.T) {
	tester := newTester("test.init.config", t)

	req, _ := http.NewRequest("GET", baseURL+"/test6", nil)
	tester.AssertResponseCode(req, 403)
}

func TestPostUrlEncoded(t *testing.T) {
	tester := newTester("test.init.config", t)

	b := strings.NewReader("adsf=qwer" + strings.Repeat("a", 1000))
	req, _ := http.NewRequest("POST", baseURL+"/test", b)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	tester.AssertResponseCode(req, 200)
}

func TestPostMultipart(t *testing.T) {
	tester := newTester("test.init.config", t)

	req, _ := http.NewRequest("POST", baseURL+"/", nil)

	fillRequestWithMultipartContent(t, req)

	tester.AssertResponseCode(req, 200)
}

func fillRequestWithMultipartContent(t *testing.T, req *http.Request) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	tempfile, err := os.CreateTemp(t.TempDir(), "tmpfile*")
	require.NoError(t, err)

	for i := 0; i < 1024*5; i++ {
		// this should create a 5mb file
		_, err := tempfile.Write([]byte(strings.Repeat("A", 1024)))
		require.NoError(t, err)
	}
	var fw io.Writer
	fw, err = w.CreateFormFile("fupload", tempfile.Name())
	require.NoError(t, err)

	_, err = tempfile.Seek(0, 0)
	require.NoError(t, err)

	_, err = io.Copy(fw, tempfile)
	require.NoError(t, err)

	req.Body = io.NopCloser(&b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Method = "POST"
}

func TestClientIpRule(t *testing.T) {
	tester := newTester("test.init.config", t)

	// client_ip will be 127.0.0.1
	req, _ := http.NewRequest("GET", baseURL+"/", nil)
	tester.AssertResponseCode(req, 200)

	// client_ip will be 127.0.0.2
	req, _ = http.NewRequest("GET", baseURL+"/", nil)
	req.Header.Add("X-Forwarded-For", "127.0.0.2")
	tester.AssertResponseCode(req, 403)
}

func newTester(caddyfile string, t *testing.T) *caddytest.Tester {
	tester := caddytest.NewTester(t)
	configContent, err := os.ReadFile(caddyfile)
	require.NoError(t, err)
	tester.InitServer(string(configContent), "caddyfile")
	return tester
}

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := map[string]struct {
		config    string
		shouldErr bool
	}{
		"empty config": {
			shouldErr: true,
		},
		"invalid config for directives without value": {
			config: `coraza_waf {
				directives
			}`,
			shouldErr: true,
		},
		"invalid config for directives with more than one value": {
			config: `coraza_waf {
				directives first_arg second_arg
			}`,
			shouldErr: true,
		},

		"invalid config for unexpected key": {
			config: `coraza_waf {
				unknown_key first_arg
			}`,
			shouldErr: true,
		},
		"invalid config for load_owasp_crs with value": {
			config: `coraza_waf {
				load_owasp_crs next_arg
			}`,
			shouldErr: true,
		},
		"valid config": {
			config: `coraza_waf {
				load_owasp_crs
				directives ` + "`Include my-rules.conf`" + `
			}`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(test.config)
			m := &corazaModule{}
			err := m.UnmarshalCaddyfile(dispenser)
			if test.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestProvision(t *testing.T) {
	newCtx := func(t *testing.T) caddy.Context {
		t.Helper()
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		t.Cleanup(cancel)
		return ctx
	}

	t.Run("basic directives", func(t *testing.T) {
		m := &corazaModule{Directives: "SecRuleEngine On"}
		require.NoError(t, m.Provision(newCtx(t)))
		require.NotNil(t, m.waf)
	})

	t.Run("include file", func(t *testing.T) {
		tmpDir := t.TempDir()
		ruleFile := filepath.Join(tmpDir, "rules.conf")
		require.NoError(t, os.WriteFile(ruleFile, []byte("SecRuleEngine On"), 0644))

		m := &corazaModule{Include: []string{ruleFile}}
		require.NoError(t, m.Provision(newCtx(t)))
		require.NotNil(t, m.waf)
	})

	t.Run("include glob", func(t *testing.T) {
		tmpDir := t.TempDir()
		for i := range 2 {
			ruleFile := filepath.Join(tmpDir, fmt.Sprintf("rule%d.conf", i))
			require.NoError(t, os.WriteFile(ruleFile, []byte("SecRuleEngine On"), 0644))
		}

		m := &corazaModule{Include: []string{filepath.Join(tmpDir, "*.conf")}}
		require.NoError(t, m.Provision(newCtx(t)))
		require.NotNil(t, m.waf)
	})

	t.Run("invalid directives", func(t *testing.T) {
		m := &corazaModule{Directives: "SecInvalidDirective foo"}
		require.Error(t, m.Provision(newCtx(t)))
	})
}

func TestCleanup(t *testing.T) {
	waf, err := corazaWAF.NewWAF(corazaWAF.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	require.NoError(t, err)

	poolKey := "test-cleanup-key"
	// Store the WAF in the pool so Cleanup can release it.
	wafPool.LoadOrStore(poolKey, &pooledWAF{waf: waf})

	m := &corazaModule{
		waf:     waf,
		logger:  zap.NewNop(),
		poolKey: poolKey,
	}

	require.NotNil(t, m.waf, "waf should be set before Cleanup")
	require.NotNil(t, m.logger, "logger should be set before Cleanup")

	// Cleanup delegates to the pool; the module fields are left as-is.
	require.NoError(t, m.Cleanup())

	// Pool entry should have been deleted (ref count was 1).
	_, exists := wafPool.References(poolKey)
	require.False(t, exists, "pool entry should be removed after Cleanup")
}

// closerWAF wraps a coraza.WAF and tracks whether Close was called.
type closerWAF struct {
	corazaWAF.WAF
	closed bool
}

// noCloser wraps a coraza.WAF without exposing io.Closer, so that the
// non-closer branch of Destruct() is reliably exercised.
type noCloser struct{ inner corazaWAF.WAF }

func (n noCloser) NewTransaction() types.Transaction {
	return n.inner.NewTransaction()
}

func (n noCloser) NewTransactionWithID(id string) types.Transaction {
	return n.inner.NewTransactionWithID(id)
}

func (c *closerWAF) Close() error {
	c.closed = true
	return nil
}

// errCloser wraps a coraza.WAF and always returns an error from Close.
type errCloser struct {
	corazaWAF.WAF
	err error
}

func (e *errCloser) Close() error { return e.err }

func TestDestructCallsClose(t *testing.T) {
	waf, err := corazaWAF.NewWAF(corazaWAF.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	require.NoError(t, err)

	cw := &closerWAF{WAF: waf}
	pw := &pooledWAF{waf: cw}

	require.NoError(t, pw.Destruct())
	require.True(t, cw.closed, "Destruct should call Close on WAFs implementing io.Closer")
	require.Nil(t, pw.waf, "waf should be nil after Destruct")
}

func TestDestructNilsWAFField(t *testing.T) {
	waf, err := corazaWAF.NewWAF(corazaWAF.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	require.NoError(t, err)

	// Wrap in noCloser to guarantee the non-io.Closer path is exercised,
	// regardless of whether the underlying coraza.WAF implements io.Closer.
	pw := &pooledWAF{waf: noCloser{inner: waf}}

	require.NoError(t, pw.Destruct())
	require.Nil(t, pw.waf, "waf should be nil after Destruct")
}

func TestDestructPropagatesCloseError(t *testing.T) {
	waf, err := corazaWAF.NewWAF(corazaWAF.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	require.NoError(t, err)

	closeErr := errors.New("close failed")
	ec := &errCloser{WAF: waf, err: closeErr}
	pw := &pooledWAF{waf: ec}

	destructErr := pw.Destruct()
	require.ErrorIs(t, destructErr, closeErr, "Destruct should propagate the Close error")
	require.Nil(t, pw.waf, "waf should be nil after Destruct even when Close fails")
}

func TestUsagePoolReuse(t *testing.T) {
	// Simulate two modules with the same config — they should share a WAF.
	m1 := &corazaModule{
		Directives: "SecRuleEngine On",
	}
	m2 := &corazaModule{
		Directives: "SecRuleEngine On",
	}

	require.Equal(t, m1.computePoolKey(), m2.computePoolKey(),
		"identical configs must produce the same pool key")

	// Different config should produce a different key.
	m3 := &corazaModule{
		Directives:   "SecRuleEngine On",
		LoadOWASPCRS: true,
	}
	require.NotEqual(t, m1.computePoolKey(), m3.computePoolKey(),
		"different configs must produce different pool keys")
}

func TestNewErrorCb(t *testing.T) {
	tests := []struct {
		name          string
		severity      int // ModSecurity severity: 0=emergency ... 7=debug
		expectedLevel zapcore.Level
	}{
		{"emergency", 0, zapcore.ErrorLevel},
		{"alert", 1, zapcore.ErrorLevel},
		{"critical", 2, zapcore.ErrorLevel},
		{"error", 3, zapcore.ErrorLevel},
		{"warning", 4, zapcore.WarnLevel},
		{"notice", 5, zapcore.InfoLevel},
		{"info", 6, zapcore.InfoLevel},
		{"debug", 7, zapcore.DebugLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)

			waf, err := corazaWAF.NewWAF(
				corazaWAF.NewWAFConfig().
					WithErrorCallback(newErrorCb(zap.New(core))).
					WithDirectives(fmt.Sprintf(
						`SecRuleEngine On
						SecRule REQUEST_URI "/trigger" "id:1,phase:1,pass,log,severity:%d"`,
						tt.severity,
					)),
			)
			require.NoError(t, err)

			tx := waf.NewTransaction()
			tx.ProcessURI("/trigger", "GET", "HTTP/1.1")
			tx.ProcessRequestHeaders()
			tx.ProcessLogging()
			tx.Close()

			require.GreaterOrEqual(t, logs.Len(), 1)
			require.Equal(t, tt.expectedLevel, logs.All()[0].Level)
		})
	}

	// Rules without an explicit severity get RuleSeverityUnset (-1) since coraza v3.7.0.
	// Previously they defaulted to 0 (Emergency). The error callback must still log them.
	t.Run("unset", func(t *testing.T) {
		core, logs := observer.New(zapcore.DebugLevel)

		waf, err := corazaWAF.NewWAF(
			corazaWAF.NewWAFConfig().
				WithErrorCallback(newErrorCb(zap.New(core))).
				WithDirectives(
					`SecRuleEngine On
					SecRule REQUEST_URI "/trigger" "id:1,phase:1,pass,log"`,
				),
		)
		require.NoError(t, err)

		tx := waf.NewTransaction()
		tx.ProcessURI("/trigger", "GET", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		tx.ProcessLogging()
		tx.Close()

		require.GreaterOrEqual(t, logs.Len(), 1)
		require.Equal(t, zapcore.WarnLevel, logs.All()[0].Level)
	})
}

func TestResponseBody(t *testing.T) {
	findFreePort := func(t *testing.T) int {
		t.Helper()
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatal(err)
		}
		return port
	}

	const (
		contentWithoutDataLeak    = "No data leak"
		contentWithDataLeak       = "data leak: SQL Error!!"
		limitActionReject         = "Reject"
		limitActionProcessPartial = "ProcessPartial"
	)
	testCases := []struct {
		name                      string
		content                   string
		responseBodyRelativeLimit int
		responseBodyLimitAction   string
		expectedStatusCode        int
	}{
		{
			name:                      "OneByteLongerThanLimitAndRejects",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: -1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusInternalServerError, // changed from http.StatusRequestEntityTooLarge at https://github.com/corazawaf/coraza/pull/1379
		},
		{
			name:                      "JustEqualToLimitAndAccepts",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: 0,
			responseBodyLimitAction:   limitActionReject,
			// NOTE: According to https://coraza.io/docs/seclang/directives/#secresponsebodylimit
			// expectedStatusCode should be http.StatusOK, but actually it triggers the limit.
			// Status changed from http.StatusRequestEntityTooLarge to http.StatusInternalServerError
			// at https://github.com/corazawaf/coraza/pull/1379.
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name:                      "OneByteShorterThanLimitAndAccepts",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: 1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusOK,
		},
		{
			name:                      "DataLeakAndRejects",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: 1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusForbidden,
		},
		{
			name:                      "LimitReachedNoDataLeakPartialProcessing",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: -3,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusOK,
		},
		{
			name:                      "DataLeakFoundInPartialProcessing",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: -2,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusForbidden,
		},
		{
			name:                      "DataLeakAroundLimitPartialProcessing",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: -3,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusOK,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bodyLenThird := len(testCase.content) / 3
			bodyChunks := map[string][]string{
				"BodyInOneShot":     {testCase.content},
				"BodyInThreeChunks": {testCase.content[0:bodyLenThird], testCase.content[bodyLenThird : 2*bodyLenThird], testCase.content[2*bodyLenThird:]},
			}

			for name, chunks := range bodyChunks {
				t.Run(name, func(t *testing.T) {
					originHandler := func(w http.ResponseWriter, r *http.Request) {
						if len(chunks) == 1 {
							w.Header().Set("Content-Length", strconv.Itoa(len(testCase.content)))
						}
						w.Header().Set("Content-Type", "text/plain")
						for _, chunk := range chunks {
							if n, err := fmt.Fprint(w, chunk); err != nil {
								t.Logf("failed to write response: %s", err)
							} else if got, want := n, len(chunk); got != want {
								t.Errorf("written response byte count mismatch, got=%d, want=%d", got, want)
							}
							if f, ok := w.(http.Flusher); ok && len(chunks) > 1 {
								f.Flush()
							}
						}
					}
					originServer := httptest.NewServer(http.HandlerFunc(originHandler))
					t.Cleanup(originServer.Close)
					originServerAddr := originServer.Listener.Addr().String()

					caddyPort := findFreePort(t)
					caddyAdminPort := caddytest.Default.AdminPort
					tester := caddytest.NewTester(t)
					config := fmt.Sprintf(`{
						admin localhost:%d
						auto_https off
						order coraza_waf first
						log {
							level ERROR
						}
					}
					(waf) {
						coraza_waf {
							directives `+"`"+`
								SecRuleEngine On
								SecResponseBodyAccess On
								SecResponseBodyMimeType text/plain
								SecResponseBodyLimit %d
								SecResponseBodyLimitAction %s
								SecRule RESPONSE_BODY "SQL Error" "id:100,phase:4,deny"
							`+"`"+`
						}
					}
					:%d {
						import waf
						reverse_proxy %s
					}`, caddyAdminPort, len(testCase.content)+testCase.responseBodyRelativeLimit, testCase.responseBodyLimitAction, caddyPort, originServerAddr)
					tester.InitServer(config, "caddyfile")

					if testCase.expectedStatusCode == http.StatusOK {
						tester.AssertGetResponse(fmt.Sprintf("http://127.0.0.1:%d", caddyPort), http.StatusOK, testCase.content)
					} else {
						req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d", caddyPort), nil)
						if err != nil {
							t.Fatal(err)
						}
						tester.AssertResponseCode(req, testCase.expectedStatusCode)
					}
				})
			}
		})
	}
}

func TestTxIDReqHeader(t *testing.T) {
	tester := newTester("test2.init.config", t)

	req, err := http.NewRequest("GET", baseURL+"/test", nil)
	if err != nil {
		t.Fatalf("unable to create request %s", err)
	}

	// In real use case, this header should be set by a HTTP proxy before coraza, not by a client.
	txID := "transaction1"
	req.Header.Add("my-tx-id", txID)

	res, _ := tester.AssertResponse(req, 200, "test123")

	if got, want := res.Header.Get("x-request-id"), txID; got != want {
		t.Errorf("transaction ID mismatch, got=%v, want=%v", got, want)
	}
}

// txCloseErrWrapper wraps a real Coraza transaction and overrides Close to
// return a configurable error. This lets tests verify that ServeHTTP logs a
// warning when tx.Close() fails, without needing to reach into Coraza internals.
type txCloseErrWrapper struct {
	types.Transaction
	closeErr error
}

func (t *txCloseErrWrapper) Close() error {
	// Close the real transaction to release its resources, then return the
	// configured error so callers observe a Close failure.
	if err := t.Transaction.Close(); err != nil {
		return errors.Join(err, t.closeErr)
	}
	return t.closeErr
}

// mockWAF wraps a real Coraza WAF and injects a txCloseErrWrapper on every
// NewTransactionWithID call so that Close() returns the given error.
type mockWAF struct {
	real     corazaWAF.WAF
	closeErr error
}

func (m *mockWAF) NewTransaction() types.Transaction {
	return &txCloseErrWrapper{Transaction: m.real.NewTransaction(), closeErr: m.closeErr}
}

func (m *mockWAF) NewTransactionWithID(id string) types.Transaction {
	return &txCloseErrWrapper{Transaction: m.real.NewTransactionWithID(id), closeErr: m.closeErr}
}

// TestServeHTTP_txCloseErrorIsLogged verifies that when tx.Close() returns an
// error, ServeHTTP emits a Warn-level log entry instead of silently discarding
// the error.
func TestServeHTTP_txCloseErrorIsLogged(t *testing.T) {
	// Use SecRuleEngine Off so ServeHTTP skips all rule processing and Caddy
	// context requirements, giving us a clean path to the defer cleanup.
	realWAF, err := corazaWAF.NewWAF(corazaWAF.NewWAFConfig().WithDirectives("SecRuleEngine Off"))
	require.NoError(t, err)

	closeErr := errors.New("simulated close error")
	waf := &mockWAF{real: realWAF, closeErr: closeErr}

	core, logs := observer.New(zapcore.WarnLevel)
	m := corazaModule{
		waf:    waf,
		logger: zap.New(core),
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	noopHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	require.NoError(t, m.ServeHTTP(w, req, noopHandler))

	require.Equal(t, 1, logs.Len(), "expected exactly one log entry")
	entry := logs.All()[0]
	require.Equal(t, zapcore.WarnLevel, entry.Level)
	require.Equal(t, "Failed to close the transaction", entry.Message)
	require.NotEmpty(t, entry.ContextMap()["tx_id"], "tx_id field must be present")
	require.Equal(t, closeErr.Error(), entry.ContextMap()["error"], "error field must match")
}
