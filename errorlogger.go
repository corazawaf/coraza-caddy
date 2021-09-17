package coraza

import (
	"github.com/jptosso/coraza-waf"
	"go.uber.org/zap"
)

type errLogger struct {
	logger *zap.Logger
}

func (er *errLogger) Emergency(msg string) {
	er.logger.Error(msg)
}
func (er *errLogger) Alert(msg string) {
	er.logger.Error(msg)
}
func (er *errLogger) Critical(msg string) {
	er.logger.Error(msg)
}
func (er *errLogger) Error(msg string) {
	er.logger.Error(msg)
}
func (er *errLogger) Warning(msg string) {
	er.logger.Warn(msg)
}
func (er *errLogger) Notice(msg string) {
	// we are using info too
	er.logger.Info(msg)
}
func (er *errLogger) Info(msg string) {
	er.logger.Info(msg)
}
func (er *errLogger) Debug(msg string) {
	er.logger.Debug(msg)
}

var _ coraza.EventLogger = &errLogger{}
