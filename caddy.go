package coraza

import (
	"context"

	"github.com/caddyserver/caddy/v2"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	caddyPlaceholdersExpandGlobalName = "global"
	caddyPlaceholderCollectionName    = "CADDY"
)

func (m corazaModule) injectCaddyValues(ctx context.Context, tx types.Transaction) {
	state, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return
	}

	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return
	}

	for _, key := range m.CaddyVars {
		if key == caddyPlaceholdersExpandGlobalName {
			continue
		}

		if val, ok := repl.GetString(key); ok {
			state.Variables().TX().Add(caddyPlaceholderCollectionName+"."+key, val)
		}
	}
}

// processCaddyPlaceholders expand global Caddy placeholders if caddyPlaceholdersExpandGlobalName used
// and prepare Coraza macroses for placeholders which can be expanded only in runtime.
func (m *corazaModule) processCaddyPlaceholders() {
	if len(m.CaddyVars) == 0 {
		return
	}

	runtimeRepl := caddy.NewEmptyReplacer()
	repl := runtimeRepl
	for _, key := range m.CaddyVars {
		if key == caddyPlaceholdersExpandGlobalName {
			repl = caddy.NewReplacer()
			repl.Map(func(key string) (any, bool) {
				return runtimeRepl.Get(key)
			})
		}

		// replace Caddy placeholder with Coraza macros to resolve it's value in runtime
		runtimeRepl.Set(key, "%{TX."+caddyPlaceholderCollectionName+"."+key+"}")
	}

	m.Directives = repl.ReplaceKnown(m.Directives, "")
}
