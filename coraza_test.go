package coraza

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)
const baseURL = "http://127.0.0.1:8080"

func TestPlugin(t *testing.T) {
	tester, err := newCaddyTester("test/caddyfile", t)
	if err != nil {
		t.Fatalf("Failed to load configuration file: %s", err)
	}
	tester.AssertGetResponse(baseURL+"/test", 200, "test123")

	time.Sleep(1 * time.Second)
}

func TestPlugin2(t *testing.T) {
	tester, err := newCaddyTester("test/caddyfile", t)
	if err != nil {
		t.Fatalf("Failed to load configuration file: %s", err)
	}
	tester.AssertGetResponse(baseURL+"/test", 200, "test123")

	time.Sleep(1 * time.Second)
}

func TestSimpleRule(t *testing.T) {
	tester, err := newCaddyTester("test/caddyfile", t)
	if err != nil {
		t.Fatalf("Failed to load configuration file: %s", err)
	}
	req, _ := http.NewRequest("GET", baseURL+"/test5", nil)
	tester.AssertResponseCode(req, 500)

	time.Sleep(1 * time.Second)
}

func TestPhase3Disruption(t *testing.T) {
	tester, err := newCaddyTester("test/caddyfile", t)
	if err != nil {
		t.Fatalf("Failed to load configuration file: %s", err)
	}
	req, _ := http.NewRequest("GET", baseURL+"/test6", nil)
	tester.AssertResponseCode(req, 500)

	time.Sleep(1 * time.Second)
}

func newCaddyTester(caddyfile string, t *testing.T) (*caddytest.Tester, error){
	tester := caddytest.NewTester(t)
	configFile := caddyfile
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	return tester, nil
}