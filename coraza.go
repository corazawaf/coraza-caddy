// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coraza

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(corazaModule{})
	httpcaddyfile.RegisterHandlerDirective("coraza_waf", parseCaddyfile)
}

// corazaModule is a Web Application Firewall implementation for Caddy.
type corazaModule struct {
	Include    []string `json:"include"`
	Directives string   `json:"directives"`

	logger *zap.Logger
	waf    coraza.WAF
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
	config := coraza.NewWAFConfig().WithErrorCallback(logger(m.logger))
	if m.Directives != "" {
		config = config.WithDirectives(m.Directives)
	}
	m.logger.Debug("Preparing to include files", zap.Int("count", len(m.Include)), zap.Strings("files", m.Include))
	if len(m.Include) > 0 {
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
	var err error
	tx := m.waf.NewTransaction()
	defer func() {
		if tx.IsInterrupted() {
			// Get unique_id from transaction variables
			uniqueID := tx.Variables().GetCollection(types.VARIABLE_UNIQUE_ID).Get("UNIQUE_ID")
			m.logger.Error("WAF rule violation detected",
				zap.String("hostname", r.Host),
				zap.String("uri", r.RequestURI),
				zap.String("client_ip", r.RemoteAddr),
				zap.String("unique_id", uniqueID),
			)
		}
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.transaction_id", "")

	it, err := processRequest(tx, r)
	if err != nil {
		return err
	}
	if it != nil {
		return interrupt(nil, tx, "")
	}

	rec := newStreamRecorder(w, tx)
	err = next.ServeHTTP(rec, r)
	if err != nil {
		return err
	}
	if tx.IsInterrupted() {
		return interrupt(nil, tx, "")
	}
	if !rec.Buffered() {
		return nil
	}

	if status := rec.Status(); status > 0 {
		w.WriteHeader(status)
	}
	reader, err := rec.Reader()
	if err != nil {
		return err
	}
	_, err = io.Copy(w, reader)
	return err
}

// Unmarshal Caddyfile implements caddyfile.Unmarshaler.
func (m *corazaModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token following filter")
	}
	m.Include = []string{}
	for d.NextBlock(0) {
		key := d.Val()
		var value string
		d.Args(&value)
		if d.NextArg() {
			return d.ArgErr()
		}
		switch key {
		case "include":
			m.Include = append(m.Include, value)
		case "directives":
			m.Directives = value
		default:
			return d.Err(fmt.Sprintf("invalid key for filter directive: %s", key))
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

func logger(logger *zap.Logger) func(types.MatchedRule) {
	return func(mr types.MatchedRule) {
		data := mr.ErrorLog(403)
		switch mr.Rule().Severity() {
		case types.RuleSeverityEmergency:
			logger.Error(data)
		case types.RuleSeverityAlert:
			logger.Error(data)
		case types.RuleSeverityCritical:
			logger.Error(data)
		case types.RuleSeverityError:
			logger.Error(data)
		case types.RuleSeverityWarning:
			logger.Warn(data)
		case types.RuleSeverityNotice:
			logger.Info(data)
		case types.RuleSeverityInfo:
			logger.Info(data)
		case types.RuleSeverityDebug:
			logger.Debug(data)
		}
	}
}

func interrupt(err error, tx types.Transaction, id string) error {
	if !tx.IsInterrupted() {
		return caddyhttp.HandlerError{
			StatusCode: 500,
			ID:         id,
			Err:        err,
		}
	}
	status := tx.Interruption().Status
	if status <= 0 {
		status = 403
	}
	return caddyhttp.HandlerError{
		StatusCode: status,
		ID:         id,
		Err:        err,
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*corazaModule)(nil)
	_ caddy.Validator             = (*corazaModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*corazaModule)(nil)
	_ caddyfile.Unmarshaler       = (*corazaModule)(nil)
)
