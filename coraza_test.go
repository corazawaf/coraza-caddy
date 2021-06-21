package coraza

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	"io/ioutil"
	"strings"
	"testing"
	"time"
	"net/http"
)

func TestPlugin(t *testing.T) {
	tester := caddytest.NewTester(t)
	baseURL := "http://127.0.0.1:8080"
	configFile := "test/caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/test", 200, "test123")

	time.Sleep(1 * time.Second)
}

func TestPluginReload(t *testing.T) {
	tester := caddytest.NewTester(t)
	baseURL := "http://127.0.0.1:8080"
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
	tester := caddytest.NewTester(t)
	baseURL := "http://127.0.0.1:8080"
	configFile := "test/caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	req, _ := http.NewRequest("GET", baseURL+"/test5", nil)
	tester.AssertResponseCode(req, 500)

	time.Sleep(1 * time.Second)
}
