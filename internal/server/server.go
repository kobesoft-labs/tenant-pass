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
	"strings"
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

	// Job tickets (all optional).
	JobVerifier *pass.JobVerifier // nil: tickets are not accepted
	JobSigner   *pass.Signer      // nil: POST /v1/job-tickets is disabled
	// JobPolicies holds per-application job settings. An application
	// without an entry can neither obtain nor redeem tickets.
	JobPolicies map[string]JobPolicy
}

// JobPolicy is one application's job ticket settings.
type JobPolicy struct {
	Issue   bool                // may exchange passes for tickets
	MaxTTL  time.Duration       // cap for issued and redeemed tickets
	Limiter *ratelimit.Distinct // distinct tenants per minute for ticket redemption
	// Issuers are the key IDs whose tickets this application may redeem
	// (tenant-pass's own job key plus the application's allowed
	// external issuers).
	Issuers map[string]bool
}

// Server is the HTTP handler.
type Server struct {
	cfg      Config
	inflight chan struct{}
	draining atomic.Bool

	repairMu   sync.Mutex
	lastRepair map[string]time.Time

	// ticketPasses makes each pass exchangeable for one job ticket.
	ticketPasses passReplay

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
	mux.HandleFunc("/v1/job-tickets", s.jobTickets)
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, codeNotFound)
	})
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
	codeInvalidTicket  = "invalid_ticket"
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

// credentialsRequest is the body of POST /v1/credentials. Exactly one of
// Pass and Ticket must be set.
type credentialsRequest struct {
	Pass   string `json:"pass"`
	Ticket string `json:"ticket"`
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

// jobTicketRequest is the body of POST /v1/job-tickets.
type jobTicketRequest struct {
	Pass string `json:"pass"`
	// TTL is the requested lifetime ("30m"). Optional; capped by the
	// application's jobs.max_ttl.
	TTL string `json:"ttl"`
}

type jobTicketResponse struct {
	Ticket    string `json:"ticket"`
	Tenant    string `json:"tenant"`
	ExpiresAt string `json:"expires_at"`
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

// exchange carries one request through the common steps and owns its
// audit record.
type exchange struct {
	s      *Server
	w      http.ResponseWriter
	r      *http.Request
	a      *audit
	start  time.Time
	result string
	reason string
	level  slog.Level
	msg    string
}

func (s *Server) newExchange(w http.ResponseWriter, r *http.Request, msg string) *exchange {
	x := &exchange{s: s, w: w, r: r, a: &audit{}, start: time.Now(), result: "error", level: slog.LevelWarn, msg: msg}
	x.a.add("request_id", newRequestID())
	return x
}

func (x *exchange) finish() {
	x.a.add("result", x.result)
	if x.reason != "" {
		x.a.add("reason", x.reason)
	}
	x.a.add("duration_ms", time.Since(x.start).Milliseconds())
	x.s.cfg.Logger.LogAttrs(context.Background(), x.level, x.msg, x.a.attrs...)
}

func (x *exchange) fail(status int, code, why string) {
	x.result, x.reason = code, why
	writeError(x.w, status, code)
}

// failErr records err (class only) at error level and responds.
func (x *exchange) failErr(status int, code, why string, err error) {
	x.level = slog.LevelError
	if err != nil {
		x.a.add("error", err.Error())
	}
	x.fail(status, code, why)
}

// begin performs the steps shared by all POST endpoints: method, content
// type, concurrency limit, application authentication, body size and
// strict JSON parsing into v. It returns the application name, a release
// function for the concurrency slot, and false if a response was sent.
func (x *exchange) begin(path string, v any) (string, func(), bool) {
	if x.r.URL.Path != path {
		x.fail(http.StatusNotFound, codeNotFound, "path")
		return "", nil, false
	}
	if x.r.Method != http.MethodPost {
		x.w.Header().Set("Allow", http.MethodPost)
		x.fail(http.StatusMethodNotAllowed, codeMethod, "method")
		return "", nil, false
	}
	if mt, _, err := mime.ParseMediaType(x.r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		x.fail(http.StatusUnsupportedMediaType, codeUnsupported, "content_type")
		return "", nil, false
	}
	// Bound concurrency before doing any real work.
	select {
	case x.s.inflight <- struct{}{}:
	default:
		x.fail(http.StatusServiceUnavailable, codeBusy, "max_concurrent_requests")
		return "", nil, false
	}
	release := func() { <-x.s.inflight }

	app, err := x.s.cfg.Auth.Authenticate(x.r)
	if err != nil {
		x.w.Header().Set("WWW-Authenticate", `Bearer realm="tenant-pass"`)
		x.fail(http.StatusUnauthorized, codeUnauthorized, "app_auth")
		release()
		return "", nil, false
	}
	x.a.add("app", app)

	body, err := io.ReadAll(http.MaxBytesReader(x.w, x.r.Body, MaxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			x.fail(http.StatusRequestEntityTooLarge, codeTooLarge, "body_size")
		} else {
			x.fail(http.StatusBadRequest, codeInvalidRequest, "body_read")
		}
		release()
		return "", nil, false
	}
	if err := strictjson.Decode(body, v); err != nil {
		x.fail(http.StatusBadRequest, codeInvalidRequest, "body_json")
		release()
		return "", nil, false
	}
	return app, release, true
}

// resolve looks up the tenant (by host or tenant ID) for app and checks
// that it is enabled. It returns false if a response was sent.
func (x *exchange) resolve(ctx context.Context, app, host, tenant string) (directory.Tenant, bool) {
	var t directory.Tenant
	var err error
	if host != "" {
		t, err = x.s.cfg.Directory.ByHost(ctx, host, app)
	} else {
		t, err = x.s.cfg.Directory.ByTenant(ctx, tenant, app)
	}
	switch {
	case errors.Is(err, directory.ErrNotFound):
		x.fail(http.StatusForbidden, codeDenied, "tenant_not_found")
		return t, false
	case err != nil:
		x.failErr(http.StatusServiceUnavailable, codeUnavailable, "directory_error", err)
		return t, false
	}
	x.a.add("tenant", t.ID)
	x.a.add("node", t.Node)
	x.a.add("account", t.Account)
	if tenant != "" && tenant != t.ID {
		// The directory must return the tenant it was asked for.
		x.failErr(http.StatusServiceUnavailable, codeUnavailable, "directory_mismatch", nil)
		return t, false
	}
	if !t.Enabled {
		x.fail(http.StatusForbidden, codeDenied, "tenant_disabled")
		return t, false
	}
	return t, true
}

func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	x := s.newExchange(w, r, "credential")
	defer x.finish()

	var req credentialsRequest
	app, release, ok := x.begin("/v1/credentials", &req)
	if !ok {
		return
	}
	defer release()
	if (req.Pass == "") == (req.Ticket == "") {
		x.fail(http.StatusBadRequest, codeInvalidRequest, "pass_or_ticket")
		return
	}
	x.a.add("repair", req.Repair)

	// Verify the pass or ticket for this application, and apply the
	// matching distinct-tenant rate limit.
	var host, tenant string
	if req.Pass != "" {
		x.a.add("via", "pass")
		claims, err := s.cfg.Verifier.Verify(req.Pass, app)
		if err != nil {
			x.fail(http.StatusBadRequest, codeInvalidPass, passReason(err))
			return
		}
		x.a.add("jti", claims.ID)
		host, tenant = claims.Host, claims.Tenant
		key := "t:" + tenant
		if host != "" {
			x.a.add("host", host)
			key = "h:" + host
		}
		if !s.cfg.Limiter.Allow(app, key) {
			x.fail(http.StatusTooManyRequests, codeRateLimited, "distinct_tenants")
			return
		}
	} else {
		x.a.add("via", "ticket")
		pol, allowed := s.cfg.JobPolicies[app]
		if s.cfg.JobVerifier == nil || !allowed {
			x.fail(http.StatusForbidden, codeDenied, "jobs_not_enabled")
			return
		}
		claims, kid, err := s.cfg.JobVerifier.Verify(req.Ticket, app)
		if err != nil {
			x.fail(http.StatusBadRequest, codeInvalidTicket, "ticket_"+strings.TrimPrefix(passReason(err), "pass_"))
			return
		}
		x.a.add("jti", claims.ID)
		x.a.add("issuer", kid)
		if !pol.Issuers[kid] {
			x.fail(http.StatusForbidden, codeDenied, "issuer_not_allowed")
			return
		}
		if claims.Expiry.Sub(claims.IssuedAt) > pol.MaxTTL {
			x.fail(http.StatusBadRequest, codeInvalidTicket, "ticket_lifetime")
			return
		}
		tenant = claims.Tenant
		if !pol.Limiter.Allow(app, "t:"+tenant) {
			x.fail(http.StatusTooManyRequests, codeRateLimited, "distinct_tenants_jobs")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.IssueTimeout)
	defer cancel()

	t, ok := x.resolve(ctx, app, host, tenant)
	if !ok {
		return
	}
	node, ok := s.cfg.Nodes[t.Node]
	if !ok {
		x.failErr(http.StatusServiceUnavailable, codeUnavailable, "unknown_node", nil)
		return
	}
	x.a.add("store", node.Store.Type())

	repair := req.Repair && s.allowRepair(t.Node+"/"+t.Account)
	cred, err := node.Store.Issue(ctx, t.Account, repair)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrRefused):
			// The directory points at an account the store refuses to
			// manage. Either the directory or the store is misconfigured
			// - or someone is trying something. Loud log, opaque answer.
			x.failErr(http.StatusForbidden, codeDenied, "account_refused", err)
		case errors.Is(err, store.ErrClockSkew):
			x.failErr(http.StatusServiceUnavailable, codeUnavailable, "clock_skew", err)
		case errors.Is(err, context.DeadlineExceeded):
			x.failErr(http.StatusServiceUnavailable, codeUnavailable, "timeout", err)
		default:
			x.failErr(http.StatusServiceUnavailable, codeUnavailable, "store_error", err)
		}
		return
	}
	x.a.add("window", cred.Window)
	x.a.add("key_id", cred.KeyID)
	x.a.add("changed", cred.Changed)
	x.a.add("expires_at", cred.ExpiresAt.UTC().Format(time.RFC3339))

	x.result, x.level = "ok", slog.LevelInfo
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

// jobTickets exchanges a pass for a job ticket for the same tenant. The
// ticket lets a job that runs after the request has finished obtain
// credentials for that tenant (and only that tenant) until it expires.
func (s *Server) jobTickets(w http.ResponseWriter, r *http.Request) {
	x := s.newExchange(w, r, "job_ticket")
	defer x.finish()

	var req jobTicketRequest
	app, release, ok := x.begin("/v1/job-tickets", &req)
	if !ok {
		return
	}
	defer release()
	pol, allowed := s.cfg.JobPolicies[app]
	if s.cfg.JobSigner == nil || !allowed || !pol.Issue {
		x.fail(http.StatusForbidden, codeDenied, "job_issue_not_enabled")
		return
	}
	if req.Pass == "" {
		x.fail(http.StatusBadRequest, codeInvalidRequest, "body_json")
		return
	}
	ttl := pol.MaxTTL
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d < time.Minute || d%time.Second != 0 {
			x.fail(http.StatusBadRequest, codeInvalidRequest, "ttl")
			return
		}
		ttl = min(d, pol.MaxTTL)
	}

	claims, err := s.cfg.Verifier.Verify(req.Pass, app)
	if err != nil {
		x.fail(http.StatusBadRequest, codeInvalidPass, passReason(err))
		return
	}
	x.a.add("jti", claims.ID)
	key := "t:" + claims.Tenant
	if claims.Host != "" {
		x.a.add("host", claims.Host)
		key = "h:" + claims.Host
	}
	// Counted against the same per-application limit as credentials:
	// exchanging passes for tickets must not be a way around it.
	if !s.cfg.Limiter.Allow(app, key) {
		x.fail(http.StatusTooManyRequests, codeRateLimited, "distinct_tenants")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.IssueTimeout)
	defer cancel()
	// One ticket per pass (per replica). Reserved now so that concurrent
	// requests with the same pass cannot both succeed; released again if
	// no ticket is issued, so a transient failure does not use up the
	// pass.
	releasePass, fresh := s.ticketPasses.reserve(app, claims.ID, claims.Expiry, time.Now())
	if !fresh {
		x.fail(http.StatusForbidden, codeDenied, "pass_already_used")
		return
	}
	issued := false
	defer func() {
		if !issued {
			releasePass()
		}
	}()
	// Resolve now, so the ticket names the canonical tenant ID and is
	// only issued for an enabled tenant this application may access.
	t, ok := x.resolve(ctx, app, claims.Host, claims.Tenant)
	if !ok {
		return
	}
	now := time.Now()
	jc := pass.JobClaims{Audience: app, Tenant: t.ID, IssuedAt: now, Expiry: now.Add(ttl)}
	ticket, err := s.cfg.JobSigner.SignJob(ctx, jc)
	if err != nil {
		x.failErr(http.StatusServiceUnavailable, codeUnavailable, "sign_error", err)
		return
	}
	issued = true
	exp := now.Add(ttl).UTC().Truncate(time.Second).Format(time.RFC3339)
	x.a.add("expires_at", exp)
	x.result, x.level = "ok", slog.LevelInfo
	writeJSON(w, http.StatusOK, jobTicketResponse{Ticket: ticket, Tenant: t.ID, ExpiresAt: exp})
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
