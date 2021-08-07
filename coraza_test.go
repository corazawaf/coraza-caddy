package coraza

import (
	"fmt"
	"io/ioutil"
	"net/http"
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
	tester.AssertResponseCode(req, 500)

	time.Sleep(1 * time.Second)
}

func TestPhase3Disruption(t *testing.T) {
	tester, err := newTester("test/caddyfile", t)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", baseURL+"/test6", nil)
	tester.AssertResponseCode(req, 500)

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
	req, _ := http.NewRequest("GET", baseURL+"/test6", nil)
	tester.AssertResponseCode(req, 500)

	time.Sleep(1 * time.Second)
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
