package coraza

import (
	"fmt"
	"net/http"
	"io"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/seclang"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("coraza_waf", parseCaddyfile)
}

type Middleware struct {
	Include    string `json:"include"`
	Directives        string `json:"directives"`
	TemplateForbidden string `json:"template_forbidden"`

	//for cache
	templateForbiddenContent []byte

	logger *zap.Logger
	waf    *engine.Waf
}

func (m *Middleware) ErrorPage(w http.ResponseWriter) {
	w.WriteHeader(500)
	w.Write(m.templateForbiddenContent)
	m.logger.Debug("Transaction disrupted")
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	var err error
	m.logger = ctx.Logger(m)
	m.waf = engine.NewWaf()
	pp, _ := seclang.NewParser(m.waf)
	if m.Include != "" {
		err = pp.FromFile(m.Include)
	} else {
		err = pp.FromString(m.Directives)
	}
	if err != nil {
		return fmt.Errorf("cannot load waf directives %w", err)
	}
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var err error
	tx := m.waf.NewTransaction()
	defer tx.ProcessLogging()
	m.logger.Debug(fmt.Sprintf("[coraza] Executing transaction %s", tx.Id))
	it, err := tx.ProcessRequest(r)
	if err != nil {
		return err
	}
	if it != nil {
		//disrupted
		m.ErrorPage(w)
		return nil
	}

	rec := NewStreamRecorder(w, tx)
	err = next.ServeHTTP(rec, r)
	if err != nil {
		return err
	}
	// If the response was interrupted during phase 3 or 4 we can stop the response
	if tx.Interruption != nil {
		m.ErrorPage(w)
		return nil
	}
	if !rec.Buffered() {
		//Nothing to do, response was already sent to the client
		return nil
	}

	if status := rec.Status(); status > 0 {
		w.WriteHeader(status)
	}
	// We will send the response provided by Coraza
	_, err = io.Copy(w, rec.Reader())
	return err
}

// Unmarshal Caddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token following filter")
	}
	for d.NextBlock(0) {
		key := d.Val()
		var value string
		d.Args(&value)
		if d.NextArg() {
			return d.ArgErr()
		}
		switch key {
		case "include":
			m.Include = value
		case "directives":
			m.Directives = value
		case "template_forbidden":
			m.TemplateForbidden = value
		default:
			return d.Err(fmt.Sprintf("invalid key for filter directive: %s", key))
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
