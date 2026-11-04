package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/auth"
	"github.com/kobesoft-labs/tenant-pass/internal/directory"
	"github.com/kobesoft-labs/tenant-pass/internal/ratelimit"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

const secretPassword = "S3CRET-PASSWORD-VALUE-THAT-MUST-NOT-BE-LOGGED"

type fakeStore struct {
	mu      sync.Mutex
	calls   []string
	repairs int
	err     error
}

func (f *fakeStore) Type() string { return "postgres" }
func (f *fakeStore) Issue(_ context.Context, account string, repair bool) (store.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, account)
	if repair {
		f.repairs++
	}
	if f.err != nil {
		return store.Credential{}, f.err
	}
	exp := time.Date(2030, 1, 1, 0, 15, 0, 0, time.UTC)
	return store.Credential{Username: account, Password: secretPassword, ExpiresAt: exp, RefreshAt: exp.Add(-5 * time.Minute), Window: 7, KeyID: "k1"}, nil
}
func (f *fakeStore) Sweep(context.Context) error { return nil }
func (f *fakeStore) Ping(context.Context) error  { return nil }
func (f *fakeStore) Close()                      {}

type env struct {
	srv    *Server
	h      http.Handler
	signer pass.Signer
	store  *fakeStore
	logs   *bytes.Buffer
}

func newEnv(t *testing.T, limit int) *env {
	t.Helper()
	seed := bytes.Repeat([]byte{7}, 32)
	sk := ed25519.NewKeyFromSeed(seed)
	a, err := auth.New([]auth.App{
		{Name: "billing", TokenSHA256: auth.HashToken("tpa_billing")},
		{Name: "crm", TokenSHA256: auth.HashToken("tpa_crm")},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := directory.NewStatic([]directory.StaticTenant{
		{ID: "acme", Hosts: []string{"acme.example.com"}, Node: "pg1", Account: "t_acme", Enabled: true, Apps: []string{"billing"}},
		{ID: "off", Hosts: []string{"off.example.com"}, Node: "pg1", Account: "t_off", Enabled: false, Apps: []string{"billing"}},
		{ID: "lost", Hosts: []string{"lost.example.com"}, Node: "nowhere", Account: "t_lost", Enabled: true, Apps: []string{"billing"}},
		{ID: "t1", Hosts: []string{"t1.example.com"}, Node: "pg1", Account: "t_1", Enabled: true, Apps: []string{"billing"}},
		{ID: "t2", Hosts: []string{"t2.example.com"}, Node: "pg1", Account: "t_2", Enabled: true, Apps: []string{"billing"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeStore{}
	logs := &bytes.Buffer{}
	s := New(Config{
		Auth:         a,
		Verifier:     &pass.Verifier{Keys: map[string]ed25519.PublicKey{"gw1": sk.Public().(ed25519.PublicKey)}},
		Directory:    dir,
		Nodes:        map[string]Node{"pg1": {Store: fs, Host: "pg.internal", Port: 5432, Database: "app"}},
		Limiter:      ratelimit.NewDistinct(limit),
		IssueTimeout: time.Second,
		MaxInFlight:  4,
		Logger:       slog.New(slog.NewJSONHandler(logs, nil)),
	})
	return &env{srv: s, h: s.Handler(), signer: pass.Signer{KeyID: "gw1", Key: sk}, store: fs, logs: logs}
}

func (e *env) pass(t *testing.T, aud, host string) string {
	t.Helper()
	now := time.Now()
	p, err := e.signer.Sign(pass.Claims{Audience: aud, Host: host, IssuedAt: now, Expiry: now.Add(30 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *env) do(t *testing.T, token, body string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range mutate {
		m(r)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func body(p string) string { return `{"pass":"` + p + `"}` }

func TestIssueOK(t *testing.T) {
	e := newEnv(t, 60)
	w := e.do(t, "tpa_billing", body(e.pass(t, "billing", "acme.example.com")))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Username != "t_acme" || resp.Password != secretPassword || resp.Host != "pg.internal" || resp.Tenant != "acme" ||
		resp.ExpiresAt != "2030-01-01T00:15:00Z" || resp.RefreshAt != "2030-01-01T00:10:00Z" || resp.Store != "postgres" {
		t.Fatalf("response %+v", resp)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing Cache-Control: no-store")
	}
	if strings.Contains(e.logs.String(), secretPassword) {
		t.Fatal("password written to audit log")
	}
	if !strings.Contains(e.logs.String(), `"result":"ok"`) || !strings.Contains(e.logs.String(), `"tenant":"acme"`) {
		t.Fatalf("audit log incomplete: %s", e.logs)
	}
}

func TestRejections(t *testing.T) {
	e := newEnv(t, 60)
	other := pass.Signer{KeyID: "gw1", Key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))}
	now := time.Now()
	forged, _ := other.Sign(pass.Claims{Audience: "billing", Host: "acme.example.com", IssuedAt: now, Expiry: now.Add(30 * time.Second)})

	cases := []struct {
		name   string
		token  string
		body   string
		mut    func(*http.Request)
		status int
		code   string
	}{
		{"no token", "", body(e.pass(t, "billing", "acme.example.com")), nil, 401, codeUnauthorized},
		{"bad token", "tpa_nope", body(e.pass(t, "billing", "acme.example.com")), nil, 401, codeUnauthorized},
		{"pass for other app", "tpa_crm", body(e.pass(t, "billing", "acme.example.com")), nil, 400, codeInvalidPass},
		{"forged pass", "tpa_billing", body(forged), nil, 400, codeInvalidPass},
		{"app not allowed for tenant", "tpa_crm", body(e.pass(t, "crm", "acme.example.com")), nil, 403, codeDenied},
		{"unknown host", "tpa_billing", body(e.pass(t, "billing", "nope.example.com")), nil, 403, codeDenied},
		{"disabled tenant", "tpa_billing", body(e.pass(t, "billing", "off.example.com")), nil, 403, codeDenied},
		{"unknown node", "tpa_billing", body(e.pass(t, "billing", "lost.example.com")), nil, 503, codeUnavailable},
		{"unknown field", "tpa_billing", `{"pass":"x","tenant":"acme"}`, nil, 400, codeInvalidRequest},
		{"duplicate field", "tpa_billing", `{"pass":"` + e.pass(t, "billing", "off.example.com") + `","pass":"` + e.pass(t, "billing", "acme.example.com") + `"}`, nil, 400, codeInvalidRequest},
		{"empty pass", "tpa_billing", `{"pass":""}`, nil, 400, codeInvalidRequest},
		{"not json", "tpa_billing", `pass=x`, nil, 400, codeInvalidRequest},
		{"too large", "tpa_billing", `{"pass":"` + strings.Repeat("A", MaxBody) + `"}`, nil, 413, codeTooLarge},
		{"form content type", "tpa_billing", body("x"), func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, 415, codeUnsupported},
		{"GET", "tpa_billing", "", func(r *http.Request) { r.Method = http.MethodGet }, 405, codeMethod},
	}
	for _, c := range cases {
		var muts []func(*http.Request)
		if c.mut != nil {
			muts = append(muts, c.mut)
		}
		w := e.do(t, c.token, c.body, muts...)
		var got map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != c.status || got["error"] != c.code {
			t.Errorf("%s: %d %s, want %d %s", c.name, w.Code, w.Body, c.status, c.code)
		}
		if len(got) != 1 {
			t.Errorf("%s: error body has extra fields: %s", c.name, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: missing no-store", c.name)
		}
	}
	if len(e.store.calls) != 0 {
		t.Fatalf("store called on rejected requests: %v", e.store.calls)
	}
}

func TestStoreErrors(t *testing.T) {
	cases := []struct {
		err    error
		status int
	}{
		{store.Refused("privileged"), 403},
		{store.ErrClockSkew, 503},
		{errors.New("connection refused"), 503},
	}
	for _, c := range cases {
		e := newEnv(t, 60)
		e.store.err = c.err
		w := e.do(t, "tpa_billing", body(e.pass(t, "billing", "acme.example.com")))
		if w.Code != c.status || strings.Contains(w.Body.String(), "privileged") || strings.Contains(w.Body.String(), "refused") {
			t.Errorf("%v: %d %s", c.err, w.Code, w.Body)
		}
	}
}

func TestDistinctTenantLimit(t *testing.T) {
	e := newEnv(t, 2)
	for _, h := range []string{"acme.example.com", "t1.example.com", "acme.example.com"} {
		if w := e.do(t, "tpa_billing", body(e.pass(t, "billing", h))); w.Code != 200 {
			t.Fatalf("%s: %d", h, w.Code)
		}
	}
	if w := e.do(t, "tpa_billing", body(e.pass(t, "billing", "t2.example.com"))); w.Code != 429 {
		t.Fatalf("third tenant: %d", w.Code)
	}
}

func TestRepairIsRateLimited(t *testing.T) {
	e := newEnv(t, 60)
	for range 3 {
		w := e.do(t, "tpa_billing", `{"pass":"`+e.pass(t, "billing", "acme.example.com")+`","repair":true}`)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if e.store.repairs != 1 {
		t.Fatalf("repairs = %d, want 1", e.store.repairs)
	}
}

func TestProbes(t *testing.T) {
	e := newEnv(t, 60)
	for _, p := range []string{"/healthz", "/readyz"} {
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	e.srv.SetDraining()
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != 503 {
		t.Errorf("draining readyz: %d", w.Code)
	}
}

func httptestRequest(path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, body)
	r.Header.Set("Content-Type", "application/json")
	return r
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func TestExtraRoutesAndReadiness(t *testing.T) {
	var readyErr error
	srv := New(Config{
		Directory:   pingDirectory{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxInFlight: 1,
		Extra: map[string]http.Handler{
			"POST /v1/storage": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }),
		},
		ExtraReady: []func(context.Context) error{func(context.Context) error { return readyErr }},
	})
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/storage", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("extra route: %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("extra route without security headers")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz: %d", rec.Code)
	}

	readyErr = errors.New("extension down")
	srv.readyAt = time.Time{} // drop the 5 s cache
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with failing extension: %d", rec.Code)
	}
}

// pingDirectory is a directory that only answers Ping.
type pingDirectory struct{ directory.Directory }

func (pingDirectory) Ping(context.Context) error { return nil }
