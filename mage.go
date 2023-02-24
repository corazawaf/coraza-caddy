// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore
// +build ignore

// Entrypoint to mage for running without needing to install the command.
// https://magefile.org/zeroinstall/
package main

import (
	"os"

	"github.com/magefile/mage/mage"
)

func main() {
	os.Exit(mage.Main())
}
