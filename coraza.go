// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors.
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
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/fuomag9/coraza/v3"
	coraza_http "github.com/fuomag9/coraza/v3/http"
	"github.com/fuomag9/coraza/v3/seclang"
	"github.com/fuomag9/coraza/v3/types"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Coraza{})
	httpcaddyfile.RegisterHandlerDirective("coraza_waf", parseCaddyfile)
}

// Coraza is a Web Application Firewall implementation for Caddy.
type Coraza struct {
	Include    []string `json:"include"`
	Directives string   `json:"directives"`

	logger *zap.Logger
	waf    *coraza.Waf
}

// CaddyModule returns the Caddy module information.
func (Coraza) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(Coraza) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Coraza) Provision(ctx caddy.Context) error {
	var err error
	m.logger = ctx.Logger(m)
	m.waf = coraza.NewWaf()
	m.waf.SetErrorLogCb(logger(m.logger))
	pp, _ := seclang.NewParser(m.waf)
	if m.Directives != "" {
		if err = pp.FromString(m.Directives); err != nil {
			return err
		}
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
					if err := pp.FromFile(f); err != nil {
						return err
					}
				}
			} else {
				m.logger.Debug("File was not a pattern, compiling it", zap.String("file", file))
				if err := pp.FromFile(file); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Validate implements caddy.Validator.
func (m *Coraza) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Coraza) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var err error
	tx := m.waf.NewTransaction(context.Background())
	defer func() {
		tx.ProcessLogging()
		_ = tx.Clean()
	}()
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.transaction_id", tx.ID)

	it, err := coraza_http.ProcessRequest(tx, r)
	if err != nil {
		return err
	}
	if it != nil {
		return interrupt(nil, tx)
	}

	// TODO this is a temporal fix while I fix it in coraza
	re, err := tx.RequestBodyBuffer.Reader()
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(re)
	rec := newStreamRecorder(w, tx)
	err = next.ServeHTTP(rec, r)
	if err != nil {
		return err
	}
	// If the response was interrupted during phase 3 or 4 we can stop the response
	if tx.Interruption != nil {
		return interrupt(nil, tx)
	}
	if !rec.Buffered() {
		//Nothing to do, response was already sent to the client
		return nil
	}

	if status := rec.Status(); status > 0 {
		w.WriteHeader(status)
	}
	// We will send the response provided by Coraza
	reader, err := rec.Reader()
	if err != nil {
		return err
	}
	_, err = io.Copy(w, reader)
	return err
}

// Unmarshal Caddyfile implements caddyfile.Unmarshaler.
func (m *Coraza) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
	var m Coraza
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func logger(logger *zap.Logger) coraza.ErrorLogCallback {
	return func(mr types.MatchedRule) {
		data := mr.ErrorLog(403)
		switch mr.Rule.Severity {
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

func interrupt(err error, tx *coraza.Transaction) error {
	if tx.Interruption == nil {
		return caddyhttp.HandlerError{
			StatusCode: 500,
			ID:         tx.ID,
			Err:        err,
		}
	}
	status := tx.Interruption.Status
	if status <= 0 {
		status = 403
	}
	return caddyhttp.HandlerError{
		StatusCode: status,
		ID:         tx.ID,
		Err:        err,
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Coraza)(nil)
	_ caddy.Validator             = (*Coraza)(nil)
	_ caddyhttp.MiddlewareHandler = (*Coraza)(nil)
	_ caddyfile.Unmarshaler       = (*Coraza)(nil)
)
