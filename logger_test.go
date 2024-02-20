// Copyright 2024 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"os"
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func BenchmarkLogger(b *testing.B) {
	f, err := os.CreateTemp(b.TempDir(), "test.log")
	require.NoError(b, err)

	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{f.Name()}

	l, err := cfg.Build()
	require.NoError(b, err)

	var (
		l1, l2, l3  debuglog.Logger
		debugLogger = newLogger(l)
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l1 = debugLogger.With(debuglog.Str("key1", "value1"))
		l1.Info().Msg("message1")

		l2 = debugLogger.With(debuglog.Str("key2", "value2"), debuglog.Str("key3", "value3"))
		l2.Info().Msg("message2&3")

		l3 = debugLogger.With(debuglog.Str("key4", "value4"))
		l3.Info().Msg("message4")
	}
}
