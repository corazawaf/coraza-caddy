// Copyright 2022 The Corazawaf Authors.
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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

const baseURL = "http://127.0.0.1:8080"

func TestPlugin(t *testing.T) {
	tester, err := newTester("test/caddyfile", t)
	if err != nil {
		t.Fatal(err)
	}
	tester.AssertGetResponse(baseURL+"/test", 200, "test123")
	//	if len(res.Header.Get("x-unique-id")) == 0 {
	//		t.Error("X-Unique-Id header is not set")
	//	}

	time.Sleep(1 * time.Second)
}

func TestPluginReload(t *testing.T) {
	tester := caddytest.NewTester(t)
	configFile := "test/caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)

	rawConfig = strings.ReplaceAll(rawConfig, "test123", "test456")

	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/test", 200, "test456")

	time.Sleep(1 * time.Second)
}

func TestSimpleRule(t *testing.T) {
	tester, err := newTester("test/caddyfile", t)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", baseURL+"/test5", nil)
	tester.AssertResponseCode(req, 403)

	time.Sleep(1 * time.Second)

	req, _ = http.NewRequest("GET", baseURL+"/test_include1", nil)
	tester.AssertResponseCode(req, 403)

	time.Sleep(1 * time.Second)

	req, _ = http.NewRequest("GET", baseURL+"/test_include2", nil)
	tester.AssertResponseCode(req, 403)

	time.Sleep(1 * time.Second)
}

func TestPhase3Disruption(t *testing.T) {
	tester, err := newTester("test/caddyfile", t)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", baseURL+"/test6", nil)
	tester.AssertResponseCode(req, 403)

	time.Sleep(1 * time.Second)
}

func TestPostUrlEncoded(t *testing.T) {
	tester, err := newTester("test/caddyfile", t)
	if err != nil {
		t.Fatal(err)
	}
	b := strings.NewReader("adsf=qwer" + strings.Repeat("a", 1000))
	req, _ := http.NewRequest("POST", baseURL+"/test", b)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	tester.AssertResponseCode(req, 200)

	time.Sleep(1 * time.Second)
}

func TestPostMultipart(t *testing.T) {
	tester, err := newTester("test/caddyfile", t)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", baseURL+"/", nil)
	if err := multipartRequest(req); err != nil {
		t.Fatal(err)
	}
	tester.AssertResponseCode(req, 200)

	time.Sleep(1 * time.Second)
}

func multipartRequest(req *http.Request) error {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	tempfile, err := os.CreateTemp("/tmp", "tmpfile*")
	if err != nil {
		return err
	}
	defer os.Remove(tempfile.Name())
	for i := 0; i < 1024*5; i++ {
		// this should create a 5mb file
		tempfile.Write([]byte(strings.Repeat("A", 1024)))
	}
	var fw io.Writer
	if fw, err = w.CreateFormFile("fupload", tempfile.Name()); err != nil {
		return err
	}
	if _, err := tempfile.Seek(0, 0); err != nil {
		return err
	}
	if _, err = io.Copy(fw, tempfile); err != nil {
		return err
	}
	req.Body = ioutil.NopCloser(&b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Method = "POST"
	return nil
}

func newTester(caddyfile string, t *testing.T) (*caddytest.Tester, error) {
	tester := caddytest.NewTester(t)
	configContent, err := ioutil.ReadFile(caddyfile)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration file %s: %s", caddyfile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	return tester, nil
}
