// Copyright 2023 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza-coreruleset/io"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/yalue/merged_fs"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(corazaModule{})
	httpcaddyfile.RegisterHandlerDirective("coraza_waf", parseCaddyfile)
}

// corazaModule is a Web Application Firewall implementation for Caddy.
type corazaModule struct {
	// deprecated
	Include    []string `json:"include"`
	Directives string   `json:"directives"`
	Tag        string   `json:"tag"`
	logger     *zap.Logger
	waf        coraza.WAF
}

// CaddyModule returns the Caddy module information.
func (corazaModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(corazaModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *corazaModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	config := coraza.NewWAFConfig().
		WithErrorCallback(newErrorCb(m.logger, m.Tag)).
		WithDebugLogger(newLogger(m.logger)).
		WithRootFS(merged_fs.NewMergedFS(coreruleset.FS, io.OSFS))

	if m.Directives != "" {
		config = config.WithDirectives(m.Directives)
	}

	if len(m.Include) > 0 {
		m.logger.Warn("include field is deprecated, please use the Include directive inside 'directives' field instead")
		for _, file := range m.Include {
			if strings.Contains(file, "*") {
				m.logger.Debug("Preparing to expand glob", zap.String("pattern", file))
				// we get files as expandables globs (with wildcard patterns)
				fs, err := filepath.Glob(file)
				if err != nil {
					return err
				}
				m.logger.Debug("Glob expanded", zap.String("pattern", file), zap.Strings("files", fs))
				for _, f := range fs {
					config = config.WithDirectivesFromFile(f)
				}
			} else {
				m.logger.Debug("File was not a pattern, compiling it", zap.String("file", file))
				config = config.WithDirectivesFromFile(file)
			}
		}
	}

	var err error
	m.waf, err = coraza.NewWAF(config)
	return err
}

// Validate implements caddy.Validator.
func (m *corazaModule) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m corazaModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	id := randomString(16)
	tx := m.waf.NewTransactionWithID(id)
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	// Early return, Coraza is not going to process any rule
	if tx.IsRuleEngineOff() {
		// response writer is not going to be wrapped, but used as-is
		// to generate the response
		return next.ServeHTTP(w, r)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.transaction_id", id)

	// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
	// ProcessRequestHeaders and ProcessRequestBody.
	// It fails if any of these functions returns an error and it stops on interruption.
	if it, err := processRequest(tx, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: 500,
			ID:         tx.ID(),
			Err:        err,
		}
	} else if it != nil {
		w.WriteHeader(obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK))
		return nil
	}

	ww, processResponse := wrap(w, r, tx)

	// We continue with the other middlewares by catching the response
	if err := next.ServeHTTP(ww, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: 500,
			ID:         tx.ID(),
			Err:        err,
		}
	}

	if err := processResponse(tx, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: 500,
			ID:         tx.ID(),
			Err:        err,
		}
	}

	return nil
}

// Unmarshal Caddyfile implements caddyfile.Unmarshaler.
func (m *corazaModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token following filter")
	}

	m.Include = []string{}
	m.Tag = ""
	for d.NextBlock(0) {
		key := d.Val()
		var value string
		if !d.Args(&value) {
			// not enough args
			return d.ArgErr()
		}

		if d.NextArg() {
			// too many args
			return d.ArgErr()
		}

		switch key {
		case "include":
			m.Include = append(m.Include, value)
		case "directives":
			m.Directives = value
		case "tag":
			m.Tag = value
		default:
			return d.Errf("invalid key for filter directive: %s", key)
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m corazaModule
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func newErrorCb(logger *zap.Logger, tag string) func(types.MatchedRule) {
	return func(mr types.MatchedRule) {
		data := mr.ErrorLog(403)
		var msg string
		if tag == "" {
			msg = data
		} else {
			msg = fmt.Sprintf("[tag %s] %s", tag, data)
		}
		switch mr.Rule().Severity() {
		case types.RuleSeverityEmergency,
			types.RuleSeverityAlert,
			types.RuleSeverityCritical,
			types.RuleSeverityError:
			logger.Error(msg)
		case types.RuleSeverityWarning:
			logger.Warn(msg)
		case types.RuleSeverityNotice:
			logger.Info(msg)
		case types.RuleSeverityInfo:
			logger.Info(msg)
		case types.RuleSeverityDebug:
			logger.Debug(msg)
		}
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*corazaModule)(nil)
	_ caddy.Validator             = (*corazaModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*corazaModule)(nil)
	_ caddyfile.Unmarshaler       = (*corazaModule)(nil)
)
