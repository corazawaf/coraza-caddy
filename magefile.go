// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var addLicenseVersion = "v1.0.0" // https://github.com/google/addlicense
var golangCILintVer = "v1.53.3"  // https://github.com/golangci/golangci-lint/releases
var gosImportsVer = "v0.1.5"     // https://github.com/rinchsan/gosimports/releases/tag/v0.1.5

var errRunGoModTidy = errors.New("go.mod/sum not formatted, commit changes")
var errNoGitDir = errors.New("no .git directory found")

// Format formats code in this repository.
func Format() error {
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}
	// addlicense strangely logs skipped files to stderr despite not being erroneous, so use the long sh.Exec form to
	// discard stderr too.
	if _, err := sh.Exec(map[string]string{}, io.Discard, io.Discard, "go", "run", fmt.Sprintf("github.com/google/addlicense@%s", addLicenseVersion),
		"-c", "The OWASP Coraza contributors",
		"-s=only",
		"-ignore", "**/*.yml",
		"-ignore", "**/*.yaml", "."); err != nil {
		return err
	}
	return sh.RunV("go", "run", fmt.Sprintf("github.com/rinchsan/gosimports/cmd/gosimports@%s", gosImportsVer),
		"-w",
		"-local",
		"github.com/corazawaf/coraza-caddy/v2",
		".")
}

// Lint verifies code quality.
func Lint() error {
	if err := sh.RunV("go", "run", fmt.Sprintf("github.com/golangci/golangci-lint/cmd/golangci-lint@%s", golangCILintVer), "run"); err != nil {
		return err
	}

	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}

	if sh.Run("git", "diff", "--exit-code", "go.mod", "go.sum") != nil {
		return errRunGoModTidy
	}

	return nil
}

// Test runs all tests.
func Test() error {
	if err := sh.RunV("go", "test", "./..."); err != nil {
		return err
	}
	return nil
}

// E2e runs e2e tests with a built plugin against the e2e deployment. Requires docker-compose.
func E2e() error {
	var err error
	if err = sh.RunV("docker-compose", "-f", "e2e/docker-compose.yml", "up", "-d", "caddy"); err != nil {
		return err
	}
	defer func() {
		_ = sh.RunV("docker-compose", "--file", "e2e/docker-compose.yml", "down", "-v")
	}()

	caddyHost := os.Getenv("CADDY_HOST")
	if caddyHost == "" {
		caddyHost = "localhost:8080"
	}
	httpbinHost := os.Getenv("HTTPBIN_HOST")
	if httpbinHost == "" {
		httpbinHost = "localhost:8081"
	}

	if err = sh.RunV("go", "run", "github.com/corazawaf/coraza/v3/http/e2e/cmd/httpe2e@main", "--proxy-hostport", "http://"+caddyHost, "--httpbin-hostport", "http://"+httpbinHost); err != nil {
		sh.RunV("docker-compose", "-f", "e2e/docker-compose.yml", "logs", "caddy")
	}
	return err
}

// Ftw runs CRS regressions tests. Requires docker-compose.
func Ftw() error {
	if err := sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "build", "--pull"); err != nil {
		return err
	}
	defer func() {
		_ = sh.RunV("docker-compose", "--file", "ftw/docker-compose.yml", "down", "-v")
	}()
	env := map[string]string{
		"FTW_CLOUDMODE": os.Getenv("FTW_CLOUDMODE"),
		"FTW_INCLUDE":   os.Getenv("FTW_INCLUDE"),
	}
	task := "ftw"
	return sh.RunWithV(env, "docker-compose", "--file", "ftw/docker-compose.yml", "run", "--rm", task)
}

// Coverage runs tests with coverage and race detector enabled.
func Coverage() error {
	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "-race", "-coverprofile=build/coverage.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
		return err
	}

	return sh.RunV("go", "tool", "cover", "-html=build/coverage.txt", "-o", "build/coverage.html")
}

// Doc runs godoc, access at http://localhost:6060
func Doc() error {
	return sh.RunV("go", "run", "golang.org/x/tools/cmd/godoc@latest", "-http=:6060")
}

// Precommit installs a git hook to run check when committing
func Precommit() error {
	if _, err := os.Stat(filepath.Join(".git", "hooks")); os.IsNotExist(err) {
		return errNoGitDir
	}

	f, err := os.ReadFile(".pre-commit.hook")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(".git", "hooks", "pre-commit"), f, 0755)
}

// Check runs lint and tests.
func Check() {
	mg.SerialDeps(Lint, Test)
}

// BuildCaddy builds the plugin.
func BuildCaddy() error {
	return buildCaddy("")
}

// BuildCaddyLinux builds the plugin with GOOS=linux.
func BuildCaddyLinux() error {
	return buildCaddy("linux")
}

func buildCaddy(goos string) error {
	env := map[string]string{}
	buildDir := "build/caddy"
	if goos != "" {
		env["GOOS"] = goos
		buildDir = fmt.Sprintf("%s-%s", buildDir, goos)
	}

	buildArgs := []string{"build"}
	if os.Getenv("CADDY_VERSION") != "" {
		buildArgs = append(buildArgs, os.Getenv("CADDY_VERSION"))
	}
	buildArgs = append(buildArgs, "--with", "github.com/corazawaf/coraza-caddy/v2=.",
		"--output", buildDir)

	return sh.RunWithV(env, "xcaddy", buildArgs...)
}

// BuildExample builds the example deployment. Requires docker-compose.
func BuildExample() error {
	mg.SerialDeps(BuildCaddyLinux)
	return sh.RunV("docker-compose", "--file", "example/docker-compose.yml", "build", "--no-cache", "caddy")
}

// RunExample spins up the test environment, access at http://localhost:8080. Requires docker-compose.
func RunExample() error {
	return sh.RunV("docker-compose", "--file", "example/docker-compose.yml", "up", "-d", "caddy-logs")
}

// TeardownExample tears down the test environment. Requires docker-compose.
func TeardownExample() error {
	return sh.RunV("docker-compose", "--file", "example/docker-compose.yml", "down")
}

// ReloadExample reload the test environment. Requires docker-compose.
func ReloadExample() error {
	return sh.RunV("docker-compose", "--file", "example/docker-compose.yml", "restart")
}
