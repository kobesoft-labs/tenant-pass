package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kobesoft-labs/tenant-pass/internal/config"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

const issuer = "https://idp.example.com/"

type idp struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	edKey  ed25519.PrivateKey
	jwks   []byte
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &r.PublicKey, KeyID: "rsa1", Algorithm: "RS256", Use: "sig"},
		{Key: &e.PublicKey, KeyID: "ec1", Use: "sig"},
		{Key: ed.Public(), KeyID: "ed1", Algorithm: "EdDSA"},
	}}
	b, _ := json.Marshal(set)
	return &idp{rsaKey: r, ecKey: e, edKey: ed, jwks: b}
}

func (i *idp) token(t *testing.T, alg jose.SignatureAlgorithm, kid string, key any, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (i *idp) userToken(t *testing.T, tenant any) string {
	now := time.Now()
	return i.token(t, jose.RS256, "rsa1", i.rsaKey, map[string]any{
		"iss": issuer, "aud": "tenant-apps", "sub": "u1", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "tenant_id": tenant,
	})
}

type fixture struct {
	g      *Gateway
	h      http.Handler
	verify *pass.Verifier
	idp    *idp
	logs   *bytes.Buffer
}

func setup(t *testing.T, mutate func(*File)) *fixture {
	t.Helper()
	dir := t.TempDir()
	i := newIdP(t)
	jwksPath := filepath.Join(dir, "jwks.json")
	os.WriteFile(jwksPath, i.jwks, 0o644)
	f := &File{
		Listen: "127.0.0.1:9180", InsecurePlaintextHTTP: true,
		Pass:    PassSettings{TTL: config.Duration(30 * time.Second), Header: "Tenant-Pass"},
		Request: RequestSettings{HostHeader: "X-Forwarded-Host"},
		Identity: IdentitySettings{
			Issuer: issuer, Audiences: []string{"tenant-apps"}, JWKSFile: jwksPath,
			Algorithms: []string{"RS256", "ES256", "EdDSA"}, AuthorizationHeader: true, Cookie: "session",
			TenantClaim: "tenant_id", Leeway: config.Duration(30 * time.Second),
		},
		Routes: []Route{
			{Host: "{tenant}.billing.example.com", App: "billing"},
			{Host: "shop.acme-corp.com", App: "billing", Tenant: "acme"},
			{Host: "app.example.com", App: "crm", TenantFromToken: true},
		},
		Unauthenticated: "pass_through", LogLevel: "debug",
	}
	if mutate != nil {
		mutate(f)
	}
	ks, err := newFileKeySet(jwksPath)
	if err != nil {
		t.Fatal(err)
	}
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	logs := &bytes.Buffer{}
	g, err := New(f, ks, pass.Signer{KeyID: "gw1", Key: sk}, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{g: g, h: g.Handler(), idp: i, logs: logs,
		verify: &pass.Verifier{Keys: map[string]ed25519.PublicKey{"gw1": sk.Public().(ed25519.PublicKey)}}}
}

func (fx *fixture) call(host, bearer, cookie string, extra ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Host", host)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "session", Value: cookie})
	}
	for _, e := range extra {
		e(r)
	}
	w := httptest.NewRecorder()
	fx.h.ServeHTTP(w, r)
	return w
}

func TestPassForOwnTenant(t *testing.T) {
	fx := setup(t, nil)
	cases := []struct {
		host, app, tenant string
		tenantClaim       any
	}{
		{"acme.billing.example.com", "billing", "acme", "acme"},
		{"ACME.billing.example.com:443", "billing", "acme", []any{"other", "acme"}},
		{"shop.acme-corp.com", "billing", "acme", "acme"},
		{"app.example.com", "crm", "beta", "beta"},
	}
	for _, c := range cases {
		w := fx.call(c.host, fx.idp.userToken(t, c.tenantClaim), "")
		p := w.Header().Get("Tenant-Pass")
		if w.Code != 200 || p == "" {
			t.Fatalf("%s: %d %s", c.host, w.Code, w.Body)
		}
		claims, err := fx.verify.Verify(p, c.app)
		if err != nil || claims.Tenant != c.tenant {
			t.Fatalf("%s: %+v %v", c.host, claims, err)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Error("missing no-store")
		}
	}
	// Cookie source works too.
	if w := fx.call("acme.billing.example.com", "", fx.idp.userToken(t, "acme")); w.Header().Get("Tenant-Pass") == "" {
		t.Fatal("cookie token not accepted")
	}
}

func TestNoPassWithoutValidSession(t *testing.T) {
	fx := setup(t, nil)
	i := fx.idp
	now := time.Now()
	base := func() map[string]any {
		return map[string]any{"iss": issuer, "aud": "tenant-apps", "exp": now.Add(time.Hour).Unix(), "tenant_id": "acme"}
	}
	with := func(k string, v any) map[string]any { m := base(); m[k] = v; return m }
	without := func(k string) map[string]any { m := base(); delete(m, k); return m }
	otherRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	tokens := map[string]string{
		"none":            "",
		"garbage":         "not.a.jwt",
		"expired":         i.token(t, jose.RS256, "rsa1", i.rsaKey, with("exp", now.Add(-time.Hour).Unix())),
		"no exp":          i.token(t, jose.RS256, "rsa1", i.rsaKey, without("exp")),
		"wrong issuer":    i.token(t, jose.RS256, "rsa1", i.rsaKey, with("iss", "https://evil.example.com/")),
		"wrong aud":       i.token(t, jose.RS256, "rsa1", i.rsaKey, with("aud", "other")),
		"forged":          i.token(t, jose.RS256, "rsa1", otherRSA, base()),
		"unknown kid":     i.token(t, jose.RS256, "nope", i.rsaKey, base()),
		"alg mismatch":    i.token(t, jose.PS256, "rsa1", i.rsaKey, base()), // key pins RS256
		"alg not allowed": i.token(t, jose.ES384, "ec1", p384, base()),
		"no tenant":       i.token(t, jose.RS256, "rsa1", i.rsaKey, without("tenant_id")),
		"tenant number":   i.token(t, jose.RS256, "rsa1", i.rsaKey, with("tenant_id", 7)),
		"hs256":           hsToken(t),
	}
	for name, tok := range tokens {
		w := fx.call("acme.billing.example.com", tok, "")
		if w.Code != 200 || w.Header().Get("Tenant-Pass") != "" {
			t.Errorf("%s: %d pass=%q", name, w.Code, w.Header().Get("Tenant-Pass"))
		}
	}
	// ES256 and EdDSA tokens with the right keys do work.
	for name, tok := range map[string]string{
		"es256": i.token(t, jose.ES256, "ec1", i.ecKey, base()),
		"eddsa": i.token(t, jose.EdDSA, "ed1", i.edKey, base()),
	} {
		if w := fx.call("acme.billing.example.com", tok, ""); w.Header().Get("Tenant-Pass") == "" {
			t.Errorf("%s rejected: %s", name, w.Body)
		}
	}
}

func hsToken(t *testing.T) string {
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, (&jose.SignerOptions{}).WithHeader("kid", "rsa1"))
	tok, _ := jwt.Signed(s).Claims(map[string]any{"iss": issuer, "aud": "tenant-apps", "exp": time.Now().Add(time.Hour).Unix(), "tenant_id": "acme"}).Serialize()
	return tok
}

func TestCrossTenantRefused(t *testing.T) {
	fx := setup(t, nil)
	cases := map[string]struct {
		host  string
		claim any
	}{
		"other tenant's host":         {"beta.billing.example.com", "acme"},
		"custom domain of other":      {"shop.acme-corp.com", "beta"},
		"shared host, two tenants":    {"app.example.com", []any{"a", "b"}},
		"case-folded tenant mismatch": {"acme.billing.example.com", "ACME"},
	}
	for name, c := range cases {
		w := fx.call(c.host, fx.idp.userToken(t, c.claim), "")
		if w.Code != 403 || w.Header().Get("Tenant-Pass") != "" {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

func TestHostHandling(t *testing.T) {
	fx := setup(t, nil)
	tok := fx.idp.userToken(t, "acme")
	bad := []string{"", "acme.billing.example.com, evil.example.com", "10.0.0.1", "a.b.billing.example.com.evil", "bücher.example"}
	for _, h := range bad {
		w := fx.call(h, tok, "")
		if w.Header().Get("Tenant-Pass") != "" {
			t.Errorf("%q: pass issued", h)
		}
	}
	// Nested label must not match the {tenant} pattern.
	if w := fx.call("x.acme.billing.example.com", tok, ""); w.Header().Get("Tenant-Pass") != "" {
		t.Error("multi-label tenant matched")
	}
	// Unknown host: no route, no pass.
	if w := fx.call("www.example.org", tok, ""); w.Code != 200 || w.Header().Get("Tenant-Pass") != "" {
		t.Error("unrouted host got a pass")
	}
}

func TestReviewFixes(t *testing.T) {
	fx := setup(t, func(f *File) {
		f.Routes = append(f.Routes, Route{Host: "api.{tenant}.api.example.com", App: "billing"})
	})
	tok := fx.idp.userToken(t, "acme")
	// Overlapping prefix/suffix must not panic.
	if w := fx.call("api.api.example.com", tok, ""); w.Header().Get("Tenant-Pass") != "" {
		t.Error("pass for overlapping host")
	}
	// Kelvin sign must not fold to "k".
	if w := fx.call("\u212acme.billing.example.com", fx.idp.userToken(t, "kcme"), ""); w.Header().Get("Tenant-Pass") != "" {
		t.Error("unicode folded to ascii")
	}
	// Repeated host header lines are refused.
	w := fx.call("acme.billing.example.com", tok, "", func(r *http.Request) { r.Header.Add("X-Forwarded-Host", "beta.billing.example.com") })
	if w.Code != 400 || w.Header().Get("Tenant-Pass") != "" {
		t.Errorf("repeated host header: %d", w.Code)
	}
}

func TestHostHeaderHost(t *testing.T) {
	fx := setup(t, func(f *File) { f.Request.HostHeader = "Host" })
	r := httptest.NewRequest(http.MethodGet, "http://acme.billing.example.com/", nil)
	r.Header.Set("Authorization", "Bearer "+fx.idp.userToken(t, "acme"))
	w := httptest.NewRecorder()
	fx.h.ServeHTTP(w, r)
	if w.Header().Get("Tenant-Pass") == "" {
		t.Fatalf("Host header source: %d %s", w.Code, w.Body)
	}
}

func TestRequiredClaims(t *testing.T) {
	fx := setup(t, func(f *File) { f.Identity.RequiredClaims = map[string]string{"azp": "web"} })
	now := time.Now()
	mk := func(azp any) string {
		m := map[string]any{"iss": issuer, "aud": "tenant-apps", "exp": now.Add(time.Hour).Unix(), "tenant_id": "acme"}
		if azp != nil {
			m["azp"] = azp
		}
		return fx.idp.token(t, jose.RS256, "rsa1", fx.idp.rsaKey, m)
	}
	if w := fx.call("acme.billing.example.com", mk("web"), ""); w.Header().Get("Tenant-Pass") == "" {
		t.Error("matching azp rejected")
	}
	for _, v := range []any{nil, "cli", 1} {
		if w := fx.call("acme.billing.example.com", mk(v), ""); w.Header().Get("Tenant-Pass") != "" {
			t.Errorf("azp %v accepted", v)
		}
	}
}

func TestJWKSRefreshNotCancellableAndStale(t *testing.T) {
	i := newIdP(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = io.Copy(w, bytes.NewReader(i.jwks))
	}))
	defer srv.Close()
	tc := srv.Client().Transport.(*http.Transport).TLSClientConfig
	ks, err := newURLKeySet(context.Background(), srv.URL, tc)
	if err != nil {
		t.Fatal(err)
	}
	// A cancelled request context must not abort the refresh.
	ks.mu.Lock()
	ks.keys = map[string]jose.JSONWebKey{}
	ks.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := ks.get(ctx, "rsa1"); !ok {
		t.Fatal("refresh was aborted by the client's cancelled context")
	}
	// Keys older than jwksMaxStale are refused.
	ks.mu.Lock()
	ks.fetchedAt = time.Now().Add(-2 * jwksMaxStale)
	ks.lastTry = time.Now()
	ks.mu.Unlock()
	if _, ok := ks.get(context.Background(), "rsa1"); ok {
		t.Fatal("stale keys still used")
	}
}

func TestForwardClaims(t *testing.T) {
	fx := setup(t, func(f *File) { f.Identity.ForwardClaims = map[string]string{"Tenant-Pass-User": "sub"} })
	w := fx.call("acme.billing.example.com", fx.idp.userToken(t, "acme"), "")
	if w.Header().Get("Tenant-Pass") == "" || w.Header().Get("Tenant-Pass-User") != "u1" {
		t.Fatalf("identity header: %v", w.Header())
	}
	// No identity headers without a pass.
	w = fx.call("beta.billing.example.com", fx.idp.userToken(t, "acme"), "")
	if w.Header().Get("Tenant-Pass-User") != "" {
		t.Fatal("identity header on refusal")
	}
	// A token whose claim is missing or unsafe gets no pass.
	now := time.Now()
	for _, sub := range []any{nil, "a\r\nX-Evil: 1", 7} {
		m := map[string]any{"iss": issuer, "aud": "tenant-apps", "exp": now.Add(time.Hour).Unix(), "tenant_id": "acme"}
		if sub != nil {
			m["sub"] = sub
		}
		tok := fx.idp.token(t, jose.RS256, "rsa1", fx.idp.rsaKey, m)
		if w := fx.call("acme.billing.example.com", tok, ""); w.Header().Get("Tenant-Pass") != "" {
			t.Errorf("sub %v: pass issued", sub)
		}
	}
}

func TestCallerAuthRequiredOffLoopback(t *testing.T) {
	f := *setup(t, nil).g.f
	f.InsecurePlaintextHTTP, f.AllowInsecurePlaintext = false, false
	f.Listen = "0.0.0.0:9180"
	f.TLS.CertFile, f.TLS.KeyFile = "c", "k"
	if _, err := f.validate(); err == nil || !strings.Contains(err.Error(), "callers must be authenticated") {
		t.Fatalf("err = %v", err)
	}
	f.TLS.ClientCAFile = "ca.pem"
	if _, err := f.validate(); err != nil {
		t.Fatal(err)
	}
	bad := f
	bad.Identity.ForwardClaims = map[string]string{"Cookie": "sub"}
	if _, err := bad.validate(); err == nil {
		t.Fatal("forwarding into Cookie accepted")
	}
}

func TestDenyMode(t *testing.T) {
	fx := setup(t, func(f *File) { f.Unauthenticated = "deny" })
	if w := fx.call("acme.billing.example.com", "", ""); w.Code != 401 {
		t.Errorf("deny mode: %d", w.Code)
	}
}

func TestCallerSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(p, []byte("0123456789abcdef-proxy"), 0o600)
	fx := setup(t, func(f *File) { f.CallerSecretFile = p })
	tok := fx.idp.userToken(t, "acme")
	if w := fx.call("acme.billing.example.com", tok, ""); w.Code != 401 || w.Header().Get("Tenant-Pass") != "" {
		t.Errorf("no secret: %d", w.Code)
	}
	w := fx.call("acme.billing.example.com", tok, "", func(r *http.Request) { r.Header.Set(CallerSecretHdr, "0123456789abcdef-proxy") })
	if w.Header().Get("Tenant-Pass") == "" {
		t.Errorf("with secret: %d", w.Code)
	}
}

func TestTokensNotLogged(t *testing.T) {
	fx := setup(t, nil)
	tok := fx.idp.userToken(t, "acme")
	w := fx.call("acme.billing.example.com", tok, "")
	logs := fx.logs.String()
	if strings.Contains(logs, tok) || strings.Contains(logs, w.Header().Get("Tenant-Pass")) {
		t.Fatal("token or pass in log")
	}
}

func TestConfigValidation(t *testing.T) {
	bad := map[string]func(*File){
		"hs256 allowed":          func(f *File) { f.Identity.Algorithms = []string{"HS256"} },
		"none allowed":           func(f *File) { f.Identity.Algorithms = []string{"none"} },
		"plaintext non-loopback": func(f *File) { f.Listen = "0.0.0.0:9180" },
		"pattern partial label":  func(f *File) { f.Routes = []Route{{Host: "x{tenant}.example.com", App: "a"}} },
		"two patterns":           func(f *File) { f.Routes = []Route{{Host: "{tenant}.{tenant}.example.com", App: "a"}} },
		"exact without tenant":   func(f *File) { f.Routes = []Route{{Host: "a.example.com", App: "a"}} },
		"no audiences":           func(f *File) { f.Identity.Audiences = nil },
		"http jwks":              func(f *File) { f.Identity.JWKSFile = ""; f.Identity.JWKSURL = "http://idp/jwks" },
		"no token source":        func(f *File) { f.Identity.AuthorizationHeader = false; f.Identity.Cookie = "" },
		"bad unauthenticated":    func(f *File) { f.Unauthenticated = "allow" },
		"ttl too long":           func(f *File) { f.Pass.TTL = config.Duration(10 * time.Minute) },
	}
	for name, m := range bad {
		f := &File{}
		*f = *setup(t, nil).g.f
		m(f)
		if _, err := f.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestJWKSFiltering(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edPub := edPriv.Public()
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: edPub, KeyID: ""},                                // no kid
		{Key: edPub, KeyID: "enc", Use: "enc"},                 // encryption key
		{Key: edPriv, KeyID: "priv"},                           // private key material
		{Key: edPub, KeyID: "dup"}, {Key: edPub, KeyID: "dup"}, // ambiguous
		{Key: edPub, KeyID: "ok"},
	}}
	b, _ := json.Marshal(set)
	keys, err := parseJWKS(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys["ok"].Key == nil {
		t.Fatalf("kept %v", keys)
	}
}

func TestJWKSURLRefetchIsRateLimited(t *testing.T) {
	i := newIdP(t)
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = io.Copy(w, bytes.NewReader(i.jwks))
	}))
	defer srv.Close()
	tc := srv.Client().Transport.(*http.Transport).TLSClientConfig
	ks, err := newURLKeySet(context.Background(), srv.URL, tc)
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		ks.get(context.Background(), "random-kid")
	}
	if hits > 2 {
		t.Fatalf("JWKS fetched %d times for unknown kids", hits)
	}
}

func TestExampleConfigParses(t *testing.T) {
	f, err := LoadFile("../../examples/gateway.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.validate(); err != nil && !strings.Contains(err.Error(), "caller_secret_file") {
		t.Fatal(err)
	}
}
