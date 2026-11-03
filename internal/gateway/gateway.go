// Package gateway implements tenant-pass-gateway: a forward-auth service
// that signs passes for requests whose end user has a valid session for
// the tenant of the requested host.
//
// It is called by a reverse proxy (Caddy forward_auth, nginx
// auth_request, Traefik ForwardAuth, Envoy ext_authz) before the request
// is forwarded to an application. For each call it:
//
//  1. optionally checks a shared secret, so only the proxy can call it;
//  2. reads the original host (X-Forwarded-Host by default), normalizes
//     it and finds the route (which application serves the host, and how
//     the tenant is determined);
//  3. reads the end user's session token (a JWT from your identity
//     provider) from the Authorization header or a cookie and verifies it:
//     signature against the provider's JWKS, allowed algorithm, issuer,
//     audience, expiry;
//  4. checks that the tenant of the host is one of the tenants named in
//     the token's tenant claim;
//  5. signs a pass {aud: app, tenant: T} and returns it in a response
//     header, which the proxy copies onto the forwarded request.
//
// The application is never trusted for any of this. Requests without a
// valid session get no pass (by default they are still forwarded, so the
// application can show a login page: without a pass it cannot obtain
// tenant credentials). A valid session for the wrong tenant is refused.
package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

// maxTokenLength bounds the session token we are willing to parse.
const maxTokenLength = 16 << 10

// Gateway is the forward-auth handler.
type Gateway struct {
	f            *File
	routes       []route
	keys         *keySet
	algs         []jose.SignatureAlgorithm
	signer       pass.Signer
	callerSecret []byte
	logger       *slog.Logger
	now          func() time.Time
}

// New builds a Gateway. keys and signer are created by the caller.
func New(f *File, keys *keySet, signer pass.Signer, logger *slog.Logger) (*Gateway, error) {
	routes, err := f.validate()
	if err != nil {
		return nil, err
	}
	g := &Gateway{f: f, routes: routes, keys: keys, signer: signer, logger: logger, now: time.Now}
	for _, a := range f.Identity.Algorithms {
		g.algs = append(g.algs, jose.SignatureAlgorithm(a))
	}
	if f.CallerSecretFile != "" {
		v, err := secret.ReadFile(f.CallerSecretFile)
		if err != nil {
			return nil, err
		}
		g.callerSecret = v.Bytes()
	}
	return g, nil
}

// Handler returns the HTTP handler.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/", g.auth)
	return mux
}

func (g *Gateway) respond(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"result": code})
}

// normalizeHost turns a Host / X-Forwarded-Host value into the canonical
// form passes require: lower case, no port, no trailing dot. Values that
// still are not canonical (IP literals, non-ASCII, garbage) are refused.
func normalizeHost(v string) (string, bool) {
	if v == "" || strings.ContainsAny(v, ", \t") {
		return "", false // empty, or a list of hosts: ambiguous
	}
	// Reject non-ASCII before lower-casing: Unicode case folding maps
	// some characters to ASCII (U+212A KELVIN SIGN lower-cases to "k"),
	// so "\u212acme..." would otherwise become "kcme...".
	for i := 0; i < len(v); i++ {
		if v[i] >= 0x80 {
			return "", false
		}
	}
	h := v
	if host, _, err := net.SplitHostPort(v); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	return h, isCanonical(h)
}

// match finds the route for host and returns the tenant the host itself
// determines ("" for tenant_from_token routes).
func (g *Gateway) match(host string) (*route, string, bool) {
	for i := range g.routes {
		r := &g.routes[i]
		if !r.pattern && r.Host == host {
			return r, r.Tenant, true
		}
	}
	for i := range g.routes {
		r := &g.routes[i]
		if !r.pattern || !strings.HasPrefix(host, r.prefix) || !strings.HasSuffix(host, r.suffix) {
			continue
		}
		// Prefix and suffix may overlap on short hosts
		// ("api.{tenant}.api.example.com" vs "api.api.example.com").
		if len(host) <= len(r.prefix)+len(r.suffix) {
			continue
		}
		label := host[len(r.prefix) : len(host)-len(r.suffix)]
		if !strings.Contains(label, ".") {
			return r, label, true
		}
	}
	return nil, "", false
}

// token extracts the session token: Authorization: Bearer first (if
// enabled), then the cookie.
func (g *Gateway) token(r *http.Request) string {
	if g.f.Identity.AuthorizationHeader {
		vals := r.Header.Values("Authorization")
		if len(vals) == 1 {
			if scheme, tok, ok := strings.Cut(vals[0], " "); ok && strings.EqualFold(scheme, "Bearer") {
				return tok
			}
		}
	}
	if g.f.Identity.Cookie != "" {
		if c, err := r.Cookie(g.f.Identity.Cookie); err == nil {
			return c.Value
		}
	}
	return ""
}

var errNoToken = errors.New("no token")

// verify checks the session token and returns the tenants it names.
func (g *Gateway) verify(ctx context.Context, raw string) ([]string, error) {
	if raw == "" {
		return nil, errNoToken
	}
	if len(raw) > maxTokenLength {
		return nil, errors.New("token too large")
	}
	tok, err := jwt.ParseSigned(raw, g.algs)
	if err != nil {
		return nil, errors.New("malformed or disallowed algorithm")
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("unexpected number of signatures")
	}
	h := tok.Headers[0]
	key, ok := g.keys.get(ctx, h.KeyID)
	if !ok {
		return nil, errors.New("unknown kid")
	}
	// If the provider pins an algorithm on the key, the token must use it.
	if key.Algorithm != "" && key.Algorithm != h.Algorithm {
		return nil, errors.New("algorithm does not match key")
	}
	var std jwt.Claims
	var custom map[string]any
	if err := tok.Claims(key.Key, &std, &custom); err != nil {
		return nil, errors.New("bad signature")
	}
	id := g.f.Identity
	now := g.now()
	if std.Expiry == nil {
		return nil, errors.New("token has no exp")
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		Issuer:      id.Issuer,
		AnyAudience: jwt.Audience(id.Audiences),
		Time:        now,
	}, time.Duration(id.Leeway)); err != nil {
		return nil, err
	}
	for name, want := range id.RequiredClaims {
		got, ok := custom[name].(string)
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return nil, errors.New("required claim " + name + " missing or different")
		}
	}
	if max := time.Duration(id.MaxTokenAge); max > 0 {
		if std.IssuedAt == nil || now.Sub(std.IssuedAt.Time()) > max {
			return nil, errors.New("token too old")
		}
	}
	return tenantsFromClaim(custom, id.TenantClaim)
}

// tenantsFromClaim reads a string or an array of strings at a dotted
// path.
func tenantsFromClaim(claims map[string]any, path string) ([]string, error) {
	var v any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("tenant claim missing")
		}
		v = m[part]
	}
	switch t := v.(type) {
	case string:
		return []string{t}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("tenant claim has a non-string element")
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, errors.New("tenant claim missing or not a string/array")
}

// auth is the forward-auth endpoint.
func (g *Gateway) auth(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	attrs := []any{}
	log := func(level slog.Level, result, reason string) {
		g.logger.Log(r.Context(), level, "gateway", append(attrs, "result", result, "reason", reason)...)
	}

	if g.callerSecret != nil {
		got := []byte(r.Header.Get(CallerSecretHdr))
		if subtle.ConstantTimeCompare(got, g.callerSecret) != 1 {
			log(slog.LevelWarn, "unauthorized_caller", "caller_secret")
			g.respond(w, http.StatusUnauthorized, "unauthorized_caller")
			return
		}
	}

	// Exactly one host value. Go moves the Host header into r.Host, so
	// "Host" (Envoy ext_authz) is read from there. Repeated header lines
	// are refused: if a proxy appended its value to a client-supplied
	// one, picking either could disagree with the proxy's routing.
	var rawHost string
	if strings.EqualFold(g.f.Request.HostHeader, "Host") {
		rawHost = r.Host
	} else if vals := r.Header.Values(g.f.Request.HostHeader); len(vals) == 1 {
		rawHost = vals[0]
	}
	host, ok := normalizeHost(rawHost)
	if !ok {
		log(slog.LevelWarn, "bad_request", "host")
		g.respond(w, http.StatusBadRequest, "bad_host")
		return
	}
	attrs = append(attrs, "host", host)
	rt, hostTenant, ok := g.match(host)
	if !ok {
		// Not a tenant application: nothing to authorize, no pass.
		log(slog.LevelDebug, "no_route", "")
		g.respond(w, http.StatusOK, "no_route")
		return
	}
	attrs = append(attrs, "app", rt.App)

	tenants, err := g.verify(r.Context(), g.token(r))
	if err != nil {
		attrs = append(attrs, "error", err.Error())
		if g.f.Unauthenticated == "deny" {
			log(slog.LevelInfo, "unauthenticated", "token")
			g.respond(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		log(slog.LevelInfo, "pass_through", "token")
		g.respond(w, http.StatusOK, "unauthenticated")
		return
	}

	tenant := hostTenant
	if rt.TenantFromToken {
		if len(tenants) != 1 {
			log(slog.LevelWarn, "forbidden", "token_names_several_tenants")
			g.respond(w, http.StatusForbidden, "forbidden")
			return
		}
		tenant = tenants[0]
	}
	attrs = append(attrs, "tenant", tenant)
	member := false
	for _, t := range tenants {
		if subtle.ConstantTimeCompare([]byte(t), []byte(tenant)) == 1 {
			member = true
		}
	}
	if !member || !pass.TenantIDPattern.MatchString(tenant) {
		// A real user, but not of this tenant. Never sign.
		log(slog.LevelWarn, "forbidden", "tenant_mismatch")
		g.respond(w, http.StatusForbidden, "forbidden")
		return
	}

	now := g.now()
	p, err := g.signer.SignContext(r.Context(), pass.Claims{
		Audience: rt.App, Tenant: tenant, IssuedAt: now, Expiry: now.Add(time.Duration(g.f.Pass.TTL)),
	})
	if err != nil {
		attrs = append(attrs, "error", err.Error())
		log(slog.LevelError, "error", "sign")
		g.respond(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	h.Set(g.f.Pass.Header, p)
	log(slog.LevelInfo, "ok", "")
	g.respond(w, http.StatusOK, "ok")
}
