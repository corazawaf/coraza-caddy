// Copyright 2024 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestLoggerWithLevel(t *testing.T) {
	l := newLogger(zap.NewNop())

	nopLogger := l.WithLevel(debuglog.LevelNoLog)
	require.IsType(t, &logger{}, nopLogger)
	require.False(t, nopLogger.Error().IsEnabled())

	debugLogger := l.WithLevel(debuglog.LevelDebug)
	require.True(t, debugLogger.Debug().IsEnabled())
}

func TestLoggerWithOutput(t *testing.T) {
	zapLogger, err := zap.NewProduction()
	require.NoError(t, err)
	l := newLogger(zapLogger)

	// io.Discard produces a nop logger
	nopLogger := l.WithOutput(io.Discard).(*logger)
	require.True(t, isZapNop(nopLogger.Logger))

	// Nop logger returns self
	nopL := newLogger(zap.NewNop())
	require.Equal(t, nopL, nopL.WithOutput(&bytes.Buffer{}))

	// Custom writer produces new logger
	require.NotEqual(t, l, l.WithOutput(&bytes.Buffer{}))
}

func TestLoggerWith(t *testing.T) {
	zapLogger, err := zap.NewProduction()
	require.NoError(t, err)
	l := newLogger(zapLogger)

	// No fields returns self
	require.Equal(t, l, l.With())

	// Nop logger returns self
	nopL := newLogger(zap.NewNop())
	require.Equal(t, nopL, nopL.With(debuglog.Str("key", "value")))

	// Fields on real logger returns new logger
	require.NotEqual(t, l, l.With(debuglog.Str("key", "value")))
}

func TestLoggerLevels(t *testing.T) {
	zapLogger, err := zap.NewProduction()
	require.NoError(t, err)

	tests := []struct {
		name           string
		level          debuglog.Level
		enabledMethod  string
		disabledMethod string
	}{
		{"Trace level enables all", debuglog.LevelTrace, "Trace", ""},
		{"Error level disables Warn", debuglog.LevelError, "Error", "Warn"},
		{"Warn level disables Info", debuglog.LevelWarn, "Warn", "Info"},
		{"Info level disables Debug", debuglog.LevelInfo, "Info", "Debug"},
		{"Debug level disables Trace", debuglog.LevelDebug, "Debug", "Trace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLogger(zapLogger).WithLevel(tt.level)

			getEvent := func(method string) debuglog.Event {
				switch method {
				case "Trace":
					return l.Trace()
				case "Debug":
					return l.Debug()
				case "Info":
					return l.Info()
				case "Warn":
					return l.Warn()
				case "Error":
					return l.Error()
				}
				return nil
			}

			require.True(t, getEvent(tt.enabledMethod).IsEnabled())
			if tt.disabledMethod != "" {
				require.False(t, getEvent(tt.disabledMethod).IsEnabled())
			}
		})
	}
}

type testStringer struct{ s string }

func (ts testStringer) String() string { return ts.s }

func TestEventMethods(t *testing.T) {
	zapLogger, err := zap.NewProduction()
	require.NoError(t, err)
	l := newLogger(zapLogger).WithLevel(debuglog.LevelTrace)

	evt := l.Trace()
	require.True(t, evt.IsEnabled())

	// All methods return the event for chaining
	require.Equal(t, evt, evt.Str("key", "value"))
	require.Equal(t, evt, evt.Bool("flag", true))
	require.Equal(t, evt, evt.Int("count", 42))
	require.Equal(t, evt, evt.Uint("ucount", 42))
	require.Equal(t, evt, evt.Stringer("stringer", testStringer{"hello"}))
	require.Equal(t, evt, evt.Err(errors.New("test error")))

	// Msg should not panic
	evt.Msg("test message")
}

func TestNoopEventMethods(t *testing.T) {
	l := newLogger(zap.NewNop()).WithLevel(debuglog.LevelError)

	evt := l.Trace()
	require.False(t, evt.IsEnabled())

	// All methods return the event for chaining
	require.Equal(t, evt, evt.Str("key", "value"))
	require.Equal(t, evt, evt.Bool("flag", true))
	require.Equal(t, evt, evt.Int("count", 42))
	require.Equal(t, evt, evt.Uint("ucount", 42))
	require.Equal(t, evt, evt.Stringer("stringer", testStringer{"hello"}))
	require.Equal(t, evt, evt.Err(errors.New("test error")))

	// Msg should not panic
	evt.Msg("noop message")
}

func BenchmarkLogger(b *testing.B) {
	f, err := os.CreateTemp(b.TempDir(), "test.log")
	require.NoError(b, err)

	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{f.Name()}

	l, err := cfg.Build()
	require.NoError(b, err)

	debugLogger := newLogger(l)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		debugLogger.With(debuglog.Str("key1", "value1")).Info().Msg("message1")
		debugLogger.With(debuglog.Str("key2", "value2"), debuglog.Str("key3", "value3")).Info().Msg("message2&3")
		debugLogger.With(debuglog.Str("key4", "value4")).Info().Msg("message4")
	}
}
