package gateway

import (
	"strings"
	"testing"
)

// Host normalization and route matching must never panic, and a matched
// {tenant} must always be exactly one non-empty label.
func FuzzHostMatch(f *testing.F) {
	for _, s := range []string{"acme.billing.example.com", "api.api.example.com", "ACME.Billing.Example.com:443", ".", "a..b", "Kcme.billing.example.com"} {
		f.Add(s)
	}
	g := &Gateway{}
	var err error
	file := &File{Routes: []Route{
		{Host: "{tenant}.billing.example.com", App: "billing"},
		{Host: "api.{tenant}.api.example.com", App: "billing"},
		{Host: "shop.acme-corp.com", App: "billing", Tenant: "acme"},
	}}
	// Build routes the same way validate does, without the other checks.
	for _, r := range file.Routes {
		cr := route{Route: r}
		if i := strings.Index(r.Host, "{tenant}"); i >= 0 {
			cr.prefix, cr.suffix, cr.pattern = r.Host[:i], r.Host[i+len("{tenant}"):], true
		}
		g.routes = append(g.routes, cr)
	}
	_ = err
	f.Fuzz(func(t *testing.T, raw string) {
		host, ok := normalizeHost(raw)
		if !ok {
			return
		}
		if !isCanonical(host) {
			t.Fatalf("normalizeHost(%q) = %q, not canonical", raw, host)
		}
		r, tenant, ok := g.match(host)
		if ok && r.pattern && (tenant == "" || strings.Contains(tenant, ".")) {
			t.Fatalf("match(%q) tenant %q", host, tenant)
		}
	})
}
