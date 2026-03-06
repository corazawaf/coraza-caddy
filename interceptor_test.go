// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
)

func TestObtainStatusCodeFromInterruption(t *testing.T) {
	tests := []struct {
		name         string
		action       string
		status       int
		defaultCode  int
		expectedCode int
	}{
		// deny with explicit status
		{"deny with status 403", "deny", 403, 200, 403},
		{"deny with status 429", "deny", 429, 200, 429},
		{"deny with status 503", "deny", 503, 200, 503},
		// deny without status defaults to 403
		{"deny without status", "deny", 0, 200, 403},
		// drop with explicit status — should behave like deny
		{"drop with status 403", "drop", 403, 200, 403},
		{"drop with status 429", "drop", 429, 200, 429},
		// drop without status defaults to 403 (not the defaultStatusCode)
		{"drop without status", "drop", 0, 200, 403},
		// redirect and other actions fall through to default
		{"redirect falls through", "redirect", 302, 200, 200},
		{"unknown action falls through", "something", 0, 500, 500},
		// pass action falls through to default
		{"pass falls through", "pass", 0, 200, 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			it := &types.Interruption{
				Action: tt.action,
				Status: tt.status,
			}
			got := obtainStatusCodeFromInterruptionOrDefault(it, tt.defaultCode)
			require.Equal(t, tt.expectedCode, got)
		})
	}
}
