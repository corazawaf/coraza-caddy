// Copyright 2024 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"
	"io"

	"github.com/corazawaf/coraza/v3/debuglog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type logger struct {
	*zap.Logger
	level debuglog.Level
}

var _ debuglog.Logger = (*logger)(nil)

func newLogger(l *zap.Logger) debuglog.Logger {
	return &logger{
		Logger: l,
		level:  debuglog.LevelInfo,
	}
}

func isZapNop(l *zap.Logger) bool {
	// As per zap documentation when a logger is created with NewNop() it will have
	// an invalid level
	return l.Level() == zapcore.InvalidLevel
}

func (l *logger) WithOutput(w io.Writer) debuglog.Logger {
	if w == io.Discard {
		return &logger{
			Logger: zap.NewNop(),
			level:  l.level,
		}
	}

	if isZapNop(l.Logger) {
		return l
	}

	return &logger{
		Logger: l.Logger.WithOptions(
			zap.WrapCore(func(c zapcore.Core) zapcore.Core {
				return zapcore.NewCore(
					zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
					zapcore.AddSync(w),
					l.Logger.Level(),
				)
			}),
		),
		level: l.level,
	}
}

func (l *logger) WithLevel(level debuglog.Level) debuglog.Logger {
	if level == debuglog.LevelNoLog {
		return &logger{
			Logger: zap.NewNop(),
			level:  level,
		}
	}
	return &logger{l.Logger, level}
}

func (l *logger) With(fields ...debuglog.ContextField) debuglog.Logger {
	if len(fields) == 0 || isZapNop(l.Logger) {
		return l
	}

	defaultEvt := event{}
	for _, f := range fields {
		f(&defaultEvt)
	}

	return &logger{
		Logger: l.Logger.With(defaultEvt.fields...),
		level:  l.level,
	}
}

func (l *logger) Trace() debuglog.Event {
	if l.level < debuglog.LevelTrace {
		return noopEvent{}
	}

	return &event{logger: l.Logger.Debug}
}

func (l *logger) Debug() debuglog.Event {
	if l.level < debuglog.LevelDebug {
		return noopEvent{}
	}

	return &event{logger: l.Logger.Debug}
}

func (l *logger) Info() debuglog.Event {
	if l.level < debuglog.LevelInfo {
		return noopEvent{}
	}

	return &event{logger: l.Logger.Info}
}

func (l *logger) Warn() debuglog.Event {
	if l.level < debuglog.LevelWarn {
		return noopEvent{}
	}

	return &event{logger: l.Logger.Warn}
}

func (l *logger) Error() debuglog.Event {
	if l.level < debuglog.LevelError {
		return noopEvent{}
	}

	return &event{logger: l.Logger.Error}
}

type event struct {
	logger func(msg string, fields ...zap.Field)
	fields []zap.Field
}

var _ debuglog.Event = (*event)(nil)

func (e *event) Msg(msg string) {
	e.logger(msg, e.fields...)
}

func (e *event) Str(key, val string) debuglog.Event {
	e.fields = append(e.fields, zap.String(key, val))
	return e
}

func (e *event) Bool(key string, b bool) debuglog.Event {
	e.fields = append(e.fields, zap.Bool(key, b))
	return e
}

func (e *event) Int(key string, i int) debuglog.Event {
	e.fields = append(e.fields, zap.Int(key, i))
	return e
}

func (e *event) Uint(key string, i uint) debuglog.Event {
	e.fields = append(e.fields, zap.Uint(key, i))
	return e
}

func (e *event) Stringer(key string, val fmt.Stringer) debuglog.Event {
	e.fields = append(e.fields, zap.Stringer(key, val))
	return e
}

func (e *event) Err(err error) debuglog.Event {
	e.fields = append(e.fields, zap.Error(err))
	return e
}

func (e *event) IsEnabled() bool {
	return true
}

type noopEvent struct{}

func (noopEvent) Msg(string)                                     {}
func (e noopEvent) Str(string, string) debuglog.Event            { return e }
func (e noopEvent) Err(error) debuglog.Event                     { return e }
func (e noopEvent) Bool(string, bool) debuglog.Event             { return e }
func (e noopEvent) Int(string, int) debuglog.Event               { return e }
func (e noopEvent) Uint(string, uint) debuglog.Event             { return e }
func (e noopEvent) Stringer(string, fmt.Stringer) debuglog.Event { return e }
func (e noopEvent) IsEnabled() bool                              { return false }
