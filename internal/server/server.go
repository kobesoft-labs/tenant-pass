// Package server implements the tenant-pass HTTP API.
//
// # Request path for POST /v1/credentials
//
//  1. Method, path and Content-Type are checked.
//  2. The calling application is authenticated (bearer token and/or
//     client certificate).
//  3. The body (at most MaxBody bytes) is parsed strictly.
//  4. The pass is verified: signature by a configured gateway key, claim
//     schema, lifetime, and aud == the authenticated application.
//  5. The per-application distinct-tenant rate limit is applied.
//  6. The directory resolves the tenant; unknown, not allowed for this
//     application, and disabled all yield the same 403.
//  7. The node's store issues the credential (with its own safety checks
//     on the account).
//
// Every step fails closed. Error responses carry a fixed error code and
// never the underlying reason; the reason goes to the audit log.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/auth"
	"github.com/kobesoft-labs/tenant-pass/internal/directory"
	"github.com/kobesoft-labs/tenant-pass/internal/ratelimit"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
	"github.com/kobesoft-labs/tenant-pass/internal/strictjson"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

// MaxBody is the largest accepted request body.
const MaxBody = 4096

// repairInterval limits forced rewrites per account and replica.
const repairInterval = 10 * time.Second

// Node is a configured store plus the client-facing address.
type Node struct {
	Store    store.Store
	Host     string
	Port     int
	Database string
}

// Config holds the server's dependencies.
type Config struct {
	Auth         *auth.Authenticator
	Verifier     *pass.Verifier
	Directory    directory.Directory
	Nodes        map[string]Node
	Limiter      *ratelimit.Distinct
	IssueTimeout time.Duration
	MaxInFlight  int
	Logger       *slog.Logger
}

// Server is the HTTP handler.
type Server struct {
	cfg      Config
	inflight chan struct{}
	draining atomic.Bool

	repairMu   sync.Mutex
	lastRepair map[string]time.Time

	readyMu  sync.Mutex
	readyAt  time.Time
	readyErr error
}

// New returns a Server.
func New(cfg Config) *Server {
	return &Server{
		cfg:        cfg,
		inflight:   make(chan struct{}, cfg.MaxInFlight),
		lastRepair: map[string]time.Time{},
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/credentials", s.credentials)
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.readyz)
	return secureHeaders(mux)
}

// SetDraining makes /readyz fail so load balancers stop sending traffic,
// while requests already routed here are still served.
func (s *Server) SetDraining() { s.draining.Store(true) }

// secureHeaders sets headers on every response. The API returns secrets,
// so nothing may be cached by any intermediary or client.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// Error codes returned to clients.
const (
	codeInvalidRequest = "invalid_request"
	codeUnauthorized   = "unauthorized"
	codeInvalidPass    = "invalid_pass"
	codeDenied         = "denied"
	codeRateLimited    = "rate_limited"
	codeUnavailable    = "unavailable"
	codeBusy           = "busy"
	codeTooLarge       = "request_too_large"
	codeUnsupported    = "unsupported_media_type"
	codeMethod         = "method_not_allowed"
	codeNotFound       = "not_found"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// request is the body of POST /v1/credentials.
type request struct {
	Pass   string `json:"pass"`
	Repair bool   `json:"repair"`
}

// response is the body of a successful POST /v1/credentials.
type response struct {
	Tenant    string `json:"tenant"`
	Store     string `json:"store"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Database  string `json:"database,omitempty"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ExpiresAt string `json:"expires_at"`
	RefreshAt string `json:"refresh_at"`
}

// audit accumulates the fields of one audit log record.
type audit struct {
	attrs []slog.Attr
}

func (a *audit) add(k string, v any) { a.attrs = append(a.attrs, slog.Any(k, v)) }

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	a := &audit{}
	a.add("request_id", newRequestID())
	result, reason := "error", ""
	level := slog.LevelWarn
	defer func() {
		a.add("result", result)
		if reason != "" {
			a.add("reason", reason)
		}
		a.add("duration_ms", time.Since(start).Milliseconds())
		s.cfg.Logger.LogAttrs(context.Background(), level, "credential", a.attrs...)
	}()
	fail := func(status int, code, why string) {
		result, reason = code, why
		writeError(w, status, code)
	}

	// 1. Method, Content-Type.
	if r.URL.Path != "/v1/credentials" {
		fail(http.StatusNotFound, codeNotFound, "path")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed, codeMethod, "method")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		fail(http.StatusUnsupportedMediaType, codeUnsupported, "content_type")
		return
	}

	// Bound concurrency before doing any real work.
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		fail(http.StatusServiceUnavailable, codeBusy, "max_concurrent_requests")
		return
	}

	// 2. Authenticate the application.
	app, err := s.cfg.Auth.Authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tenant-pass"`)
		fail(http.StatusUnauthorized, codeUnauthorized, "app_auth")
		return
	}
	a.add("app", app)

	// 3. Read and parse the body.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(http.StatusRequestEntityTooLarge, codeTooLarge, "body_size")
		} else {
			fail(http.StatusBadRequest, codeInvalidRequest, "body_read")
		}
		return
	}
	var req request
	if err := strictjson.Decode(body, &req); err != nil || req.Pass == "" {
		fail(http.StatusBadRequest, codeInvalidRequest, "body_json")
		return
	}
	a.add("repair", req.Repair)

	// 4. Verify the pass for this application.
	claims, err := s.cfg.Verifier.Verify(req.Pass, app)
	if err != nil {
		fail(http.StatusBadRequest, codeInvalidPass, passReason(err))
		return
	}
	a.add("jti", claims.ID)
	key := "t:" + claims.Tenant
	if claims.Host != "" {
		a.add("host", claims.Host)
		key = "h:" + claims.Host
	}

	// 5. Rate limit distinct tenants per application.
	if !s.cfg.Limiter.Allow(app, key) {
		fail(http.StatusTooManyRequests, codeRateLimited, "distinct_tenants")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.IssueTimeout)
	defer cancel()

	// 6. Resolve the tenant.
	var t directory.Tenant
	if claims.Host != "" {
		t, err = s.cfg.Directory.ByHost(ctx, claims.Host, app)
	} else {
		t, err = s.cfg.Directory.ByTenant(ctx, claims.Tenant, app)
	}
	switch {
	case errors.Is(err, directory.ErrNotFound):
		fail(http.StatusForbidden, codeDenied, "tenant_not_found")
		return
	case err != nil:
		level = slog.LevelError
		a.add("error", err.Error())
		fail(http.StatusServiceUnavailable, codeUnavailable, "directory_error")
		return
	}
	a.add("tenant", t.ID)
	a.add("node", t.Node)
	a.add("account", t.Account)
	if claims.Tenant != "" && claims.Tenant != t.ID {
		// The directory must return the tenant it was asked for.
		level = slog.LevelError
		fail(http.StatusServiceUnavailable, codeUnavailable, "directory_mismatch")
		return
	}
	if !t.Enabled {
		fail(http.StatusForbidden, codeDenied, "tenant_disabled")
		return
	}
	node, ok := s.cfg.Nodes[t.Node]
	if !ok {
		level = slog.LevelError
		fail(http.StatusServiceUnavailable, codeUnavailable, "unknown_node")
		return
	}
	a.add("store", node.Store.Type())

	// 7. Issue.
	repair := req.Repair && s.allowRepair(t.Node+"/"+t.Account)
	cred, err := node.Store.Issue(ctx, t.Account, repair)
	if err != nil {
		level = slog.LevelError
		a.add("error", err.Error())
		switch {
		case errors.Is(err, store.ErrRefused):
			// The directory points at an account the store refuses to
			// manage. Either the directory or the store is misconfigured
			// - or someone is trying something. Loud log, opaque answer.
			fail(http.StatusForbidden, codeDenied, "account_refused")
		case errors.Is(err, store.ErrClockSkew):
			fail(http.StatusServiceUnavailable, codeUnavailable, "clock_skew")
		case errors.Is(err, context.DeadlineExceeded):
			fail(http.StatusServiceUnavailable, codeUnavailable, "timeout")
		default:
			fail(http.StatusServiceUnavailable, codeUnavailable, "store_error")
		}
		return
	}
	a.add("window", cred.Window)
	a.add("key_id", cred.KeyID)
	a.add("changed", cred.Changed)
	a.add("expires_at", cred.ExpiresAt.UTC().Format(time.RFC3339))

	result, level = "ok", slog.LevelInfo
	writeJSON(w, http.StatusOK, response{
		Tenant:    t.ID,
		Store:     node.Store.Type(),
		Host:      node.Host,
		Port:      node.Port,
		Database:  node.Database,
		Username:  cred.Username,
		Password:  cred.Password,
		ExpiresAt: cred.ExpiresAt.UTC().Format(time.RFC3339),
		RefreshAt: cred.RefreshAt.UTC().Format(time.RFC3339),
	})
}

// passReason maps a verification error to an audit reason.
func passReason(err error) string {
	switch {
	case errors.Is(err, pass.ErrAudience):
		return "pass_audience"
	case errors.Is(err, pass.ErrExpired):
		return "pass_expired"
	case errors.Is(err, pass.ErrSignature):
		return "pass_signature"
	case errors.Is(err, pass.ErrUnknownKey):
		return "pass_unknown_key"
	case errors.Is(err, pass.ErrClaims):
		return "pass_claims"
	default:
		return "pass_malformed"
	}
}

// allowRepair rate-limits forced rewrites of one account. A client that
// sees an authentication failure asks for repair; rewriting is
// idempotent, but unlimited rewrites would let a misbehaving client
// generate a steady stream of catalog writes.
func (s *Server) allowRepair(key string) bool {
	s.repairMu.Lock()
	defer s.repairMu.Unlock()
	now := time.Now()
	for k, t := range s.lastRepair {
		if now.Sub(t) >= repairInterval {
			delete(s.lastRepair, k)
		}
	}
	if _, recent := s.lastRepair[key]; recent {
		return false
	}
	s.lastRepair[key] = now
	return true
}

// healthz is the liveness probe: the process is up.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, codeMethod)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz is the readiness probe: not draining, and the directory and
// every node answer. Results are cached for 5s so that probes cannot be
// used to generate load on the backends.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, codeMethod)
		return
	}
	if s.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	if err := s.checkReady(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) checkReady(ctx context.Context) error {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	if time.Since(s.readyAt) < 5*time.Second {
		return s.readyErr
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := s.cfg.Directory.Ping(ctx)
	for name, n := range s.cfg.Nodes {
		if err != nil {
			break
		}
		if e := n.Store.Ping(ctx); e != nil {
			err = e
			s.cfg.Logger.Warn("readiness", "node", name, "error", e.Error())
		}
	}
	s.readyAt, s.readyErr = time.Now(), err
	return err
}
