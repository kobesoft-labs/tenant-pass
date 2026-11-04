// Package tenantpass runs a tenant-pass server from a configuration file.
//
// It is what the tenant-pass command runs. It is exported so that the
// server can be embedded in another binary together with extensions:
// additional HTTP routes served on the same listener, with the same TLS,
// security headers, readiness and graceful shutdown. Extensions do not
// change the behaviour of the core endpoints in any way.
//
// Use extensions for closely related, deployment-specific endpoints that
// must live behind the same trust boundary as tenant-pass (for example a
// legacy protocol kept for compatibility during a migration). An
// extension sees no keys, tokens or configuration of the core.
package tenantpass

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/auth"
	"github.com/kobesoft-labs/tenant-pass/internal/config"
	"github.com/kobesoft-labs/tenant-pass/internal/directory"
	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/ratelimit"
	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	"github.com/kobesoft-labs/tenant-pass/internal/server"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
	"github.com/kobesoft-labs/tenant-pass/internal/store/mysql"
	"github.com/kobesoft-labs/tenant-pass/internal/store/postgres"
	"github.com/kobesoft-labs/tenant-pass/internal/store/redis"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

// app is everything built from the configuration.
type app struct {
	cfg    *config.Resolved
	dir    directory.Directory
	nodes  map[string]server.Node
	stores []store.Store
}

func (a *app) close() {
	for _, s := range a.stores {
		s.Close()
	}
	if a.dir != nil {
		a.dir.Close()
	}
}

// build loads and validates the configuration and constructs the
// directory and stores. It opens connection pools but does not require
// the backends to be reachable, except that the SQL directory runs its
// queries once to validate them.
func build(ctx context.Context, path string, logger *slog.Logger) (*app, error) {
	secret.Warn = func(msg, p string) { logger.Warn(msg, "path", p) }
	f, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Resolve(f, time.Now())
	if err != nil {
		return nil, fmt.Errorf("invalid configuration:\n%w", err)
	}
	a := &app{cfg: cfg, nodes: map[string]server.Node{}}

	for _, n := range cfg.Nodes {
		var s store.Store
		switch n.File.Type {
		case postgres.Type:
			s, err = postgres.New(ctx, postgres.Config{
				Name: n.File.Name, Endpoint: n.Endpoint, ManagedGroup: n.File.ManagedGroup,
				AccountPattern: n.AccountPattern, MaxConns: int32(n.File.MaxConns),
			}, cfg.Schedule)
		case mysql.Type:
			s, err = mysql.New(mysql.Config{
				Name: n.File.Name, Endpoint: n.Endpoint, AccountHost: n.File.AccountHost,
				ManagedRole: n.File.ManagedRole, ManagedRoleHost: n.File.ManagedRoleHost,
				AccountPattern: n.AccountPattern, MaxConns: n.File.MaxConns,
			}, cfg.Schedule)
		case redis.Type:
			s, err = redis.New(redis.Config{
				Name: n.File.Name, Servers: n.Servers, AccountPattern: n.AccountPattern,
				ManagedMarker: n.File.ManagedMarker, ACLSave: n.File.ACLSave,
			}, cfg.Schedule)
		}
		if err != nil {
			a.close()
			return nil, err
		}
		a.stores = append(a.stores, s)
		a.nodes[n.File.Name] = server.Node{Store: s, Host: n.File.Connect.Host, Port: n.File.Connect.Port, Database: n.File.Connect.Database}
	}

	if cfg.DirectorySQL != nil {
		vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		a.dir, err = directory.NewSQL(vctx, *cfg.DirectorySQL)
	} else {
		a.dir, err = directory.NewStatic(cfg.DirectoryStatic)
	}
	if err != nil {
		a.close()
		return nil, err
	}
	return a, nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

// CheckConfig validates the configuration file at path with the same
// construction steps as Serve, so that a configuration that passes cannot
// then be rejected by Serve. With connect, it also connects to the
// directory and every node.
func CheckConfig(ctx context.Context, path string, connect bool) error {
	logger := newLogger("warn")
	a, err := build(ctx, path, logger)
	if err != nil {
		return err
	}
	defer a.close()
	// The same construction steps as serve, so that check-config cannot
	// pass a configuration that serve then rejects.
	if _, err := auth.New(toAuthApps(a.cfg.Apps)); err != nil {
		return err
	}
	jctx, jcancel := context.WithTimeout(ctx, 15*time.Second)
	_, _, _, err = buildJobs(jctx, a.cfg)
	jcancel()
	if err != nil {
		return err
	}
	if connect {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := a.dir.Ping(ctx); err != nil {
			return fmt.Errorf("directory: %w", err)
		}
		for name, n := range a.nodes {
			if err := n.Store.Ping(ctx); err != nil {
				return fmt.Errorf("node %s: %w", name, err)
			}
		}
	}
	return nil
}

// Serve runs the server until ctx is cancelled, then shuts down
// gracefully (readiness fails first, then in-flight requests finish).
// Cancel ctx on SIGTERM to get the documented shutdown behaviour.
func Serve(ctx context.Context, opts Options) error {
	if err := opts.validate(); err != nil {
		return err
	}
	bootLogger := newLogger("info")

	a, err := build(ctx, opts.ConfigPath, bootLogger)
	if err != nil {
		return err
	}
	defer a.close()
	f := a.cfg.File
	logger := newLogger(f.LogLevel)

	authn, err := auth.New(toAuthApps(a.cfg.Apps))
	if err != nil {
		return err
	}
	jobVerifier, jobSigner, jobPolicies, err := buildJobs(ctx, a.cfg)
	if err != nil {
		return err
	}
	extra, ready, closers, err := mountExtensions(ctx, opts.Extensions, Host{Logger: logger})
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range closers {
			c()
		}
	}()

	srv := server.New(server.Config{
		Auth: authn,
		Verifier: &pass.Verifier{
			Keys:   a.cfg.GatewayKeys,
			MaxTTL: time.Duration(f.Pass.MaxTTL),
			Leeway: f.Pass.VerifierLeeway(),
		},
		Directory:    a.dir,
		Nodes:        a.nodes,
		Limiter:      ratelimit.NewDistinct(f.Limits.MaxTenantsPerMinute),
		IssueTimeout: time.Duration(f.Limits.IssueTimeout),
		MaxInFlight:  f.Limits.MaxConcurrentRequests,
		Logger:       logger,
		JobVerifier:  jobVerifier,
		JobSigner:    jobSigner,
		JobPolicies:  jobPolicies,
		Extra:        extra,
		ExtraReady:   ready,
	})

	hs := &http.Server{
		Addr:              f.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      time.Duration(f.Limits.IssueTimeout) + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	if !f.InsecurePlaintextHTTP {
		tc, err := serverTLS(f.TLS)
		if err != nil {
			return err
		}
		hs.TLSConfig = tc
	} else {
		logger.Warn("serving plaintext HTTP (insecure_plaintext_http): testing only")
	}

	// Sweepers for soft-expiry stores.
	for name, n := range a.nodes {
		if n.Store.Type() == postgres.Type {
			continue
		}
		go sweepLoop(ctx, logger, name, n.Store, time.Duration(f.Rotation.SweepInterval))
	}

	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", f.Listen, "version", opts.Version)
		if hs.TLSConfig != nil {
			errc <- hs.ListenAndServeTLS("", "") // certificate from TLSConfig
		} else {
			errc <- hs.ListenAndServe()
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// Graceful shutdown: fail readiness first so load balancers stop
	// routing here, then stop accepting and wait for in-flight requests.
	logger.Info("shutting down", "drain", time.Duration(f.Shutdown.Drain).String())
	srv.SetDraining()
	time.Sleep(time.Duration(f.Shutdown.Drain))
	sctx, cancel := context.WithTimeout(context.Background(), time.Duration(f.Shutdown.Timeout))
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil {
		return err
	}
	logger.Info("stopped")
	return nil
}

// buildJobs constructs the job ticket verifier, tenant-pass's own ticket
// signer (local or Vault Transit) and the per-application policies.
func buildJobs(ctx context.Context, cfg *config.Resolved) (*pass.JobVerifier, *pass.Signer, map[string]server.JobPolicy, error) {
	if cfg.Jobs == nil {
		return nil, nil, nil, nil
	}
	j := cfg.Jobs
	keys := map[string]ed25519.PublicKey{}
	for id, k := range j.Issuers {
		keys[id] = k
	}
	var signer *pass.Signer
	switch {
	case j.LocalSigner != nil:
		signer = &pass.Signer{KeyID: j.SigningKeyID, Key: j.LocalSigner}
		keys[j.SigningKeyID] = j.LocalSigner.Public().(ed25519.PublicKey)
	case j.Transit != nil:
		sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ts, err := cfg.Vault.NewTransitSigner(sctx, j.Transit.Key, j.Transit.Version)
		cancel()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("job_tickets.signing_key: %w", err)
		}
		signer = &pass.Signer{KeyID: j.SigningKeyID, Remote: ts.Sign}
		keys[j.SigningKeyID] = ts.Public()
		// The Transit key's material is only known now; check it is not
		// also trusted as a gateway key or another issuer.
		others := []ed25519.PublicKey{ts.Public()}
		for _, k := range j.Issuers {
			others = append(others, k)
		}
		if err := config.DistinctKeys(cfg.GatewayKeys, others); err != nil {
			return nil, nil, nil, err
		}
	}
	policies := map[string]server.JobPolicy{}
	for _, a := range cfg.Apps {
		if a.Jobs == nil {
			continue
		}
		issuers := map[string]bool{}
		if j.SigningKeyID != "" {
			issuers[j.SigningKeyID] = true
		}
		for _, id := range a.Jobs.TrustedIssuers {
			issuers[id] = true
		}
		policies[a.Name] = server.JobPolicy{
			Issue:   a.Jobs.Issue,
			MaxTTL:  min(time.Duration(a.Jobs.MaxTTL), j.MaxTTL),
			Limiter: ratelimit.NewDistinct(a.Jobs.MaxTenantsPerMinute),
			Issuers: issuers,
		}
	}
	v := &pass.JobVerifier{Keys: keys, MaxTTL: j.MaxTTL, Leeway: cfg.File.Pass.VerifierLeeway()}
	return v, signer, policies, nil
}

func toAuthApps(apps []config.ResolvedApp) []auth.App {
	out := make([]auth.App, 0, len(apps))
	for _, a := range apps {
		out = append(out, auth.App{Name: a.Name, TokenSHA256: a.TokenSHA256, ClientCertURI: a.ClientCertURI})
	}
	return out
}

// serverTLS builds the listener's TLS configuration from checked files.
func serverTLS(t config.ServerTLS) (*tls.Config, error) {
	cert, err := netcfg.LoadKeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if t.ClientCAFile != "" {
		pool, err := netcfg.LoadCertPool(t.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls.client_ca_file: %w", err)
		}
		tc.ClientCAs = pool
		// Certificates are verified whenever presented; whether one is
		// required is decided per application by the authenticator.
		tc.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tc, nil
}

// sweepLoop periodically removes expired passwords. The interval is
// jittered (+-20%) so that replicas do not sweep in lockstep.
func sweepLoop(ctx context.Context, logger *slog.Logger, name string, s store.Store, every time.Duration) {
	for {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(every)*2/5+1))
		wait := every*4/5 + time.Duration(j.Int64())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		sctx, cancel := context.WithTimeout(ctx, every)
		start := time.Now()
		err := s.Sweep(sctx)
		cancel()
		if err != nil {
			logger.Error("sweep", "node", name, "error", err.Error(), "duration_ms", time.Since(start).Milliseconds())
		} else {
			logger.Debug("sweep", "node", name, "duration_ms", time.Since(start).Milliseconds())
		}
	}
}
