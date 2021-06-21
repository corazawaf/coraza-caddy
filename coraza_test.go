package coraza

import (
	"github.com/caddyserver/caddy/v2/caddytest"
	"io/ioutil"
	"strings"
	"testing"
	"time"
)

func TestSetVars(t *testing.T){
	caddytest.Default.AdminPort = 50002
}

func TestPlugin(t *testing.T) {
	tester := caddytest.NewTester(t)
	baseURL := "https://127.0.0.1:50000"
	configFile := "test/caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)
	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/", 200, "1.0.0")

	time.Sleep(1 * time.Second)
}

func TestPluginReload(t *testing.T) {
	tester := caddytest.NewTester(t)
	baseURL := "https://127.0.0.1:50000"
	configFile := "test/caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)

	rawConfig = strings.ReplaceAll(rawConfig, "https://jptosso.github.io/coraza-waf/", "https://jptosso.github.io/coraza-waf/404")

	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/", 200, "1.0.0")

	time.Sleep(1 * time.Second)
}
