// Command tenant-pass issues short-lived, tenant-scoped credentials for
// PostgreSQL, MySQL and Redis to applications that present a pass signed
// by a trusted gateway.
//
// Usage:
//
//	tenant-pass serve           -config FILE
//	tenant-pass check-config    -config FILE [-connect]
//	tenant-pass gen-gateway-key -private FILE -public FILE
//	tenant-pass gen-rotation-key -out FILE
//	tenant-pass gen-app-token
//	tenant-pass sign-pass       -key FILE -kid ID -aud APP (-host H | -tenant T) [-ttl 30s]
//	tenant-pass sign-job-ticket -key FILE -kid ID -aud APP -tenant T [-ttl 1h]
//	tenant-pass version
//
// See docs/en/ for the full documentation.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/auth"
	"github.com/kobesoft-labs/tenant-pass/internal/config"
	"github.com/kobesoft-labs/tenant-pass/internal/directory"
	"github.com/kobesoft-labs/tenant-pass/internal/ratelimit"
	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	"github.com/kobesoft-labs/tenant-pass/internal/server"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
	"github.com/kobesoft-labs/tenant-pass/internal/store/mysql"
	"github.com/kobesoft-labs/tenant-pass/internal/store/postgres"
	"github.com/kobesoft-labs/tenant-pass/internal/store/redis"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "check-config":
		err = cmdCheckConfig(args)
	case "gen-gateway-key":
		err = cmdGenGatewayKey(args)
	case "gen-rotation-key":
		err = cmdGenRotationKey(args)
	case "gen-app-token":
		err = cmdGenAppToken(os.Stdout)
	case "sign-pass":
		err = cmdSignPass(args)
	case "sign-job-ticket":
		err = cmdSignJobTicket(args)
	case "gen-signing-key":
		err = cmdGenGatewayKey(args)
	case "version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tenant-pass:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: tenant-pass <command> [flags]

commands:
  serve             run the server
  check-config      validate a configuration file (-connect also tests connections)
  gen-gateway-key   create an Ed25519 key pair for a gateway
  gen-signing-key   same as gen-gateway-key (job ticket keys, scheduler keys)
  gen-rotation-key  create a rotation key file
  gen-app-token     create an application token and its hash
  sign-pass         sign a pass with a gateway key (testing and integration)
  sign-job-ticket   sign a job ticket with a scheduler key
  version           print the version
`)
}

func versionString() string {
	v := version
	if bi, ok := debug.ReadBuildInfo(); ok {
		v += " " + bi.GoVersion
	}
	return "tenant-pass " + v
}

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

func cmdCheckConfig(args []string) error {
	fs := flag.NewFlagSet("check-config", flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	connect := fs.Bool("connect", false, "also connect to the directory and every node")
	fs.Parse(args)
	logger := newLogger("warn")
	a, err := build(context.Background(), *path, logger)
	if err != nil {
		return err
	}
	defer a.close()
	if *connect {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
	fmt.Println("configuration OK")
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	fs.Parse(args)

	bootLogger := newLogger("info")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	a, err := build(ctx, *path, bootLogger)
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

	srv := server.New(server.Config{
		Auth: authn,
		Verifier: &pass.Verifier{
			Keys:   a.cfg.GatewayKeys,
			MaxTTL: time.Duration(f.Pass.MaxTTL),
			Leeway: time.Duration(f.Pass.Leeway),
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
		logger.Info("listening", "addr", f.Listen, "version", version)
		if hs.TLSConfig != nil {
			errc <- hs.ListenAndServeTLS(f.TLS.CertFile, f.TLS.KeyFile)
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
	v := &pass.JobVerifier{Keys: keys, MaxTTL: j.MaxTTL, Leeway: time.Duration(cfg.File.Pass.Leeway)}
	return v, signer, policies, nil
}

func toAuthApps(apps []config.ResolvedApp) []auth.App {
	out := make([]auth.App, 0, len(apps))
	for _, a := range apps {
		out = append(out, auth.App{Name: a.Name, TokenSHA256: a.TokenSHA256, ClientCertURI: a.ClientCertURI})
	}
	return out
}

// serverTLS builds the listener's TLS configuration.
func serverTLS(t config.ServerTLS) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if t.ClientCAFile != "" {
		pemBytes, err := os.ReadFile(t.ClientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("tls.client_ca_file contains no certificates")
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

// writeNewFile creates path with mode 0600, failing if it exists, so a
// key generator can never overwrite an existing key.
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func cmdGenGatewayKey(args []string) error {
	fs := flag.NewFlagSet("gen-gateway-key", flag.ExitOnError)
	priv := fs.String("private", "", "output file for the private key (PEM, PKCS #8)")
	pub := fs.String("public", "", "output file for the public key (PEM, PKIX)")
	fs.Parse(args)
	if *priv == "" || *pub == "" {
		return errors.New("-private and -public are required")
	}
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	skDER, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return err
	}
	pkDER, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return err
	}
	if err := writeNewFile(*priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: skDER}), 0o600); err != nil {
		return err
	}
	return writeNewFile(*pub, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkDER}), 0o644)
}

func cmdGenRotationKey(args []string) error {
	fs := flag.NewFlagSet("gen-rotation-key", flag.ExitOnError)
	out := fs.String("out", "", "output file")
	fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	return writeNewFile(*out, []byte(base64.StdEncoding.EncodeToString(b)+"\n"), 0o600)
}

func cmdGenAppToken(w io.Writer) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tok := auth.TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	fmt.Fprintf(w, "token:        %s\n", tok)
	fmt.Fprintf(w, "token_sha256: %s\n", hex.EncodeToString(auth.HashToken(tok)))
	fmt.Fprintln(w, "\nGive the token to the application (as a secret). Put token_sha256 in the tenant-pass configuration.")
	return nil
}

func cmdSignPass(args []string) error {
	fs := flag.NewFlagSet("sign-pass", flag.ExitOnError)
	keyFile := fs.String("key", "", "gateway private key (PEM)")
	kid := fs.String("kid", "", "gateway key ID")
	aud := fs.String("aud", "", "application name")
	host := fs.String("host", "", "tenant host name")
	tenant := fs.String("tenant", "", "tenant ID")
	ttl := fs.Duration("ttl", 30*time.Second, "lifetime")
	fs.Parse(args)
	sk, err := config.ReadEd25519PrivateKey(*keyFile)
	if err != nil {
		return err
	}
	now := time.Now()
	p, err := pass.Signer{KeyID: *kid, Key: sk}.Sign(pass.Claims{
		Audience: *aud, Host: *host, Tenant: *tenant, IssuedAt: now, Expiry: now.Add(*ttl),
	})
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}

func cmdSignJobTicket(args []string) error {
	fs := flag.NewFlagSet("sign-job-ticket", flag.ExitOnError)
	keyFile := fs.String("key", "", "issuer private key (PEM)")
	kid := fs.String("kid", "", "issuer key ID")
	aud := fs.String("aud", "", "application name")
	tenant := fs.String("tenant", "", "tenant ID")
	ttl := fs.Duration("ttl", time.Hour, "lifetime (at most 24h; tenant-pass enforces its own max_ttl)")
	fs.Parse(args)
	sk, err := config.ReadEd25519PrivateKey(*keyFile)
	if err != nil {
		return err
	}
	now := time.Now()
	t, err := pass.Signer{KeyID: *kid, Key: sk}.SignJob(context.Background(), pass.JobClaims{
		Audience: *aud, Tenant: *tenant, IssuedAt: now, Expiry: now.Add(*ttl),
	})
	if err != nil {
		return err
	}
	fmt.Println(t)
	return nil
}
