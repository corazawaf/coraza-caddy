// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/require"
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
