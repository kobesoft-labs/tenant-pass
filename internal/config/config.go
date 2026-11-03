// Package config loads and validates the tenant-pass configuration file.
//
// Principles:
//
//   - One JSON file, parsed strictly: unknown keys, duplicate keys and
//     trailing data are errors, so a typo cannot silently disable a
//     security setting.
//   - No secrets in the file. Every secret is a path to a separate file
//     (see package secret).
//   - Everything is validated before the server starts. A value that is
//     missing, malformed or unsafe stops startup with an error; nothing
//     silently falls back to a default.
//   - Insecure modes (plaintext HTTP, plaintext store connections) need
//     two explicit switches: the per-item setting and the global
//     allow_insecure_plaintext flag, and are meant for local testing only.
package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/directory"
	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	"github.com/kobesoft-labs/tenant-pass/internal/strictjson"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

// MaxFileSize bounds the configuration file.
const MaxFileSize = 4 << 20

// Duration is a time.Duration written as a Go duration string ("15m").
type Duration time.Duration

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("duration must be a string such as \"15m\"")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// File is the configuration file as written by the operator.
type File struct {
	Listen string    `json:"listen"`
	TLS    ServerTLS `json:"tls"`
	// AllowInsecurePlaintext must be true for any plaintext setting to be
	// accepted. Testing only.
	AllowInsecurePlaintext bool `json:"allow_insecure_plaintext"`
	// InsecurePlaintextHTTP serves the API without TLS. Testing only, or
	// behind a TLS-terminating proxy on the same host.
	InsecurePlaintextHTTP bool `json:"insecure_plaintext_http"`

	GatewayKeys []GatewayKey  `json:"gateway_keys"`
	Pass        PassSettings  `json:"pass"`
	Apps        []AppConfig   `json:"apps"`
	Directory   DirectoryFile `json:"directory"`
	Rotation    RotationFile  `json:"rotation"`
	Nodes       []NodeFile    `json:"nodes"`
	Limits      Limits        `json:"limits"`
	Shutdown    Shutdown      `json:"shutdown"`
	LogLevel    string        `json:"log_level"`
}

// ServerTLS configures the API listener's TLS.
type ServerTLS struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// ClientCAFile enables client certificate authentication.
	ClientCAFile string `json:"client_ca_file"`
}

// GatewayKey is a trusted gateway public key.
type GatewayKey struct {
	ID            string `json:"id"`
	PublicKeyFile string `json:"public_key_file"`
}

// PassSettings tunes pass verification.
type PassSettings struct {
	MaxTTL Duration `json:"max_ttl"`
	Leeway Duration `json:"leeway"`
}

// AppConfig is one application.
type AppConfig struct {
	Name          string `json:"name"`
	TokenSHA256   string `json:"token_sha256"`
	ClientCertURI string `json:"client_cert_uri"`
}

// DirectoryFile selects and configures the directory. Exactly one member
// must be set.
type DirectoryFile struct {
	Static *struct {
		Tenants []directory.StaticTenant `json:"tenants"`
	} `json:"static"`
	SQL *struct {
		Driver   string          `json:"driver"`
		Endpoint netcfg.Endpoint `json:"endpoint"`
		ByHost   string          `json:"by_host"`
		ByTenant string          `json:"by_tenant"`
	} `json:"sql"`
}

// RotationFile configures password rotation.
type RotationFile struct {
	Window      Duration      `json:"window"`
	RenewBefore Duration      `json:"renew_before"`
	Keys        []RotationKey `json:"keys"`
	// SweepInterval is how often soft-expiry stores (MySQL, Redis) are
	// swept for expired passwords.
	SweepInterval Duration `json:"sweep_interval"`
	// MaxClockSkew is the largest tolerated difference between a
	// replica's clock and a store server's clock.
	MaxClockSkew Duration `json:"max_clock_skew"`
}

// RotationKey is one rotation key.
type RotationKey struct {
	ID         string    `json:"id"`
	SecretFile string    `json:"secret_file"`
	NotBefore  time.Time `json:"not_before"`
}

// NodeFile configures one store node.
type NodeFile struct {
	Name string `json:"name"`
	Type string `json:"type"` // postgres | mysql | redis
	// Endpoint is the admin connection (postgres, mysql).
	Endpoint *netcfg.Endpoint `json:"endpoint"`
	// Servers are the admin connections (redis): every server that holds
	// the ACL users.
	Servers []netcfg.Endpoint `json:"servers"`
	// AccountPattern restricts which accounts may be managed (required).
	AccountPattern string `json:"account_pattern"`
	// PostgreSQL.
	ManagedGroup string `json:"managed_group"`
	// MySQL.
	AccountHost     string `json:"account_host"`
	ManagedRole     string `json:"managed_role"`
	ManagedRoleHost string `json:"managed_role_host"`
	// Redis.
	ACLSave       bool   `json:"acl_save"`
	ManagedMarker string `json:"managed_marker"`
	// MaxConns bounds the admin connection pool (postgres, mysql).
	MaxConns int `json:"max_conns"`
	// Connect is what clients receive: where to connect.
	Connect Connect `json:"connect"`
}

// Connect is the client-facing address of a node.
type Connect struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database,omitempty"`
}

// Limits holds request limits.
type Limits struct {
	MaxTenantsPerMinute   int      `json:"max_tenants_per_minute"`
	IssueTimeout          Duration `json:"issue_timeout"`
	MaxConcurrentRequests int      `json:"max_concurrent_requests"`
}

// Shutdown controls graceful shutdown.
type Shutdown struct {
	Drain   Duration `json:"drain"`
	Timeout Duration `json:"timeout"`
}

// Load reads and strictly parses the configuration file and applies
// defaults. It does not touch secrets or the network; see Resolve.
func Load(path string) (*File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > MaxFileSize {
		return nil, fmt.Errorf("config: %s is too large", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("config: %s is writable by group or others", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := strictjson.Decode(b, &f); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	f.applyDefaults()
	return &f, nil
}

func (f *File) applyDefaults() {
	if f.Listen == "" {
		f.Listen = ":8443"
	}
	if f.Pass.MaxTTL == 0 {
		f.Pass.MaxTTL = Duration(pass.DefaultMaxTTL)
	}
	if f.Pass.Leeway == 0 {
		f.Pass.Leeway = Duration(pass.DefaultLeeway)
	}
	if f.Rotation.Window == 0 {
		f.Rotation.Window = Duration(15 * time.Minute)
	}
	if f.Rotation.RenewBefore == 0 {
		f.Rotation.RenewBefore = Duration(5 * time.Minute)
	}
	if f.Rotation.SweepInterval == 0 {
		f.Rotation.SweepInterval = Duration(30 * time.Second)
	}
	if f.Rotation.MaxClockSkew == 0 {
		f.Rotation.MaxClockSkew = Duration(10 * time.Second)
	}
	if f.Limits.MaxTenantsPerMinute == 0 {
		f.Limits.MaxTenantsPerMinute = 60
	}
	if f.Limits.IssueTimeout == 0 {
		f.Limits.IssueTimeout = Duration(5 * time.Second)
	}
	if f.Limits.MaxConcurrentRequests == 0 {
		f.Limits.MaxConcurrentRequests = 256
	}
	if f.Shutdown.Drain == 0 {
		f.Shutdown.Drain = Duration(5 * time.Second)
	}
	if f.Shutdown.Timeout == 0 {
		f.Shutdown.Timeout = Duration(10 * time.Second)
	}
	if f.LogLevel == "" {
		f.LogLevel = "info"
	}
	for i := range f.Nodes {
		n := &f.Nodes[i]
		if n.Type == "redis" && n.ManagedMarker == "" {
			n.ManagedMarker = "tenant-pass:managed"
		}
		if n.Type == "mysql" {
			if n.AccountHost == "" {
				n.AccountHost = "%"
			}
			if n.ManagedRoleHost == "" {
				n.ManagedRoleHost = "%"
			}
		}
	}
}

// Resolved is a fully validated configuration with secrets loaded.
// Directory and stores are constructed by the caller from DirectorySQL /
// DirectoryStatic and Nodes, because they open network connections.
type Resolved struct {
	File        *File
	GatewayKeys map[string]ed25519.PublicKey
	Apps        []ResolvedApp
	Schedule    *rotation.Schedule

	DirectoryStatic []directory.StaticTenant
	DirectorySQL    *directory.SQLConfig

	Nodes []ResolvedNode
}

// ResolvedApp is an application with its token hash decoded.
type ResolvedApp struct {
	Name          string
	TokenSHA256   []byte
	ClientCertURI string
}

// ResolvedNode is a node with its endpoints resolved.
type ResolvedNode struct {
	File           NodeFile
	AccountPattern *regexp.Regexp
	Endpoint       *netcfg.Resolved   // postgres, mysql
	Servers        []*netcfg.Resolved // redis
}

// Resolve validates f completely and loads every secret it references.
func Resolve(f *File, now time.Time) (*Resolved, error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	r := &Resolved{File: f, GatewayKeys: map[string]ed25519.PublicKey{}}

	// --- listener -------------------------------------------------------
	if f.InsecurePlaintextHTTP {
		if !f.AllowInsecurePlaintext {
			fail("insecure_plaintext_http requires allow_insecure_plaintext (testing only)")
		}
		if f.TLS != (ServerTLS{}) {
			fail("insecure_plaintext_http cannot be combined with tls")
		}
	} else {
		if f.TLS.CertFile == "" || f.TLS.KeyFile == "" {
			fail("tls.cert_file and tls.key_file are required")
		} else if _, err := secret.ReadFile(f.TLS.KeyFile); err != nil {
			fail("tls.key_file: %v", err)
		}
	}

	// --- gateway keys ---------------------------------------------------
	if len(f.GatewayKeys) == 0 {
		fail("at least one gateway key is required")
	}
	for _, k := range f.GatewayKeys {
		if !pass.NamePattern.MatchString(k.ID) {
			fail("gateway key id %q is invalid", k.ID)
			continue
		}
		if _, dup := r.GatewayKeys[k.ID]; dup {
			fail("gateway key id %q is duplicated", k.ID)
			continue
		}
		pk, err := ReadEd25519PublicKey(k.PublicKeyFile)
		if err != nil {
			fail("gateway key %q: %v", k.ID, err)
			continue
		}
		r.GatewayKeys[k.ID] = pk
	}
	if f.Pass.MaxTTL <= 0 || time.Duration(f.Pass.MaxTTL) > pass.HardMaxTTL {
		fail("pass.max_ttl must be between 1s and %s", pass.HardMaxTTL)
	}
	if f.Pass.Leeway < 0 || time.Duration(f.Pass.Leeway) > 30*time.Second {
		fail("pass.leeway must be between 0 and 30s")
	}

	// --- apps -----------------------------------------------------------
	if len(f.Apps) == 0 {
		fail("at least one app is required")
	}
	for _, a := range f.Apps {
		if !pass.NamePattern.MatchString(a.Name) {
			fail("app name %q is invalid (must match %s)", a.Name, pass.NamePattern)
			continue
		}
		ra := ResolvedApp{Name: a.Name, ClientCertURI: a.ClientCertURI}
		if a.TokenSHA256 != "" {
			h, err := hex.DecodeString(a.TokenSHA256)
			if err != nil || len(h) != 32 || a.TokenSHA256 != strings.ToLower(a.TokenSHA256) {
				fail("app %q: token_sha256 must be 64 lowercase hex characters", a.Name)
				continue
			}
			ra.TokenSHA256 = h
		}
		if a.ClientCertURI != "" && f.TLS.ClientCAFile == "" {
			fail("app %q: client_cert_uri requires tls.client_ca_file", a.Name)
		}
		r.Apps = append(r.Apps, ra)
	}

	// --- rotation -------------------------------------------------------
	var keys []rotation.Key
	for _, k := range f.Rotation.Keys {
		if !pass.NamePattern.MatchString(k.ID) {
			fail("rotation key id %q is invalid", k.ID)
			continue
		}
		v, err := secret.ReadKeyFile(k.SecretFile, rotation.MinSecretLength)
		if err != nil {
			fail("rotation key %q: %v", k.ID, err)
			continue
		}
		if k.NotBefore.IsZero() {
			fail("rotation key %q: not_before is required", k.ID)
			continue
		}
		keys = append(keys, rotation.Key{ID: k.ID, Secret: v.Bytes(), NotBefore: k.NotBefore})
	}
	if len(errs) == 0 {
		s, err := rotation.NewSchedule(time.Duration(f.Rotation.Window), time.Duration(f.Rotation.RenewBefore), keys)
		if err != nil {
			fail("%v", err)
		} else if err := s.CheckCurrentKey(now); err != nil {
			fail("%v", err)
		} else {
			s.MaxClockSkew = time.Duration(f.Rotation.MaxClockSkew)
			r.Schedule = s
		}
	}
	if mcs := time.Duration(f.Rotation.MaxClockSkew); mcs < time.Second || mcs > time.Duration(f.Rotation.RenewBefore)/4 {
		fail("rotation.max_clock_skew must be between 1s and renew_before/4")
	}
	if si := time.Duration(f.Rotation.SweepInterval); si < 5*time.Second || si > time.Duration(f.Rotation.RenewBefore) {
		fail("rotation.sweep_interval must be between 5s and renew_before")
	}

	// --- directory ------------------------------------------------------
	switch {
	case (f.Directory.Static == nil) == (f.Directory.SQL == nil):
		fail("directory: exactly one of static or sql must be set")
	case f.Directory.Static != nil:
		r.DirectoryStatic = f.Directory.Static.Tenants
	default:
		d := f.Directory.SQL
		if d.Driver != "postgres" && d.Driver != "mysql" {
			fail("directory.sql.driver must be postgres or mysql")
		}
		ep, err := d.Endpoint.Resolve(f.AllowInsecurePlaintext)
		if err != nil {
			fail("directory.sql.endpoint: %v", err)
		}
		r.DirectorySQL = &directory.SQLConfig{Driver: d.Driver, Endpoint: ep, ByHost: d.ByHost, ByTenant: d.ByTenant}
	}

	// --- nodes ----------------------------------------------------------
	if len(f.Nodes) == 0 {
		fail("at least one node is required")
	}
	names := map[string]bool{}
	for _, n := range f.Nodes {
		rn, err := resolveNode(n, f.AllowInsecurePlaintext)
		if err != nil {
			fail("node %q: %v", n.Name, err)
			continue
		}
		if names[n.Name] {
			fail("node %q is duplicated", n.Name)
			continue
		}
		names[n.Name] = true
		r.Nodes = append(r.Nodes, rn)
	}
	for _, t := range r.DirectoryStatic {
		if !names[t.Node] {
			fail("static tenant %q refers to unknown node %q", t.ID, t.Node)
		}
		for _, a := range t.Apps {
			found := false
			for _, app := range f.Apps {
				found = found || app.Name == a
			}
			if !found {
				fail("static tenant %q refers to unknown app %q", t.ID, a)
			}
		}
	}

	// --- limits ---------------------------------------------------------
	if f.Limits.MaxTenantsPerMinute < 1 {
		fail("limits.max_tenants_per_minute must be positive")
	}
	if it := time.Duration(f.Limits.IssueTimeout); it < 100*time.Millisecond || it > time.Minute {
		fail("limits.issue_timeout must be between 100ms and 1m")
	}
	if f.Limits.MaxConcurrentRequests < 1 {
		fail("limits.max_concurrent_requests must be positive")
	}
	if f.Shutdown.Drain < 0 || f.Shutdown.Timeout <= 0 {
		fail("shutdown durations must be positive")
	}
	switch f.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		fail("log_level must be debug, info, warn or error")
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return r, nil
}

func resolveNode(n NodeFile, allowPlain bool) (ResolvedNode, error) {
	rn := ResolvedNode{File: n}
	if !pass.NamePattern.MatchString(n.Name) {
		return rn, fmt.Errorf("name must match %s", pass.NamePattern)
	}
	if n.AccountPattern == "" {
		return rn, errors.New("account_pattern is required")
	}
	if !strings.HasPrefix(n.AccountPattern, "^") || !strings.HasSuffix(n.AccountPattern, "$") {
		return rn, errors.New("account_pattern must be anchored with ^ and $")
	}
	// Compile as ^(?:pattern)$ so that alternation cannot escape the
	// anchors: "^t_[a-z]+|svc$" would otherwise match "t_x_anything".
	re, err := regexp.Compile("^(?:" + n.AccountPattern + ")$")
	if err != nil {
		return rn, fmt.Errorf("account_pattern: %v", err)
	}
	rn.AccountPattern = re
	if n.Connect.Host == "" || n.Connect.Port < 1 || n.Connect.Port > 65535 {
		return rn, errors.New("connect.host and connect.port are required")
	}

	switch n.Type {
	case "postgres", "mysql":
		if n.Endpoint == nil || len(n.Servers) > 0 {
			return rn, errors.New("endpoint (and not servers) is required")
		}
		if rn.Endpoint, err = n.Endpoint.Resolve(allowPlain); err != nil {
			return rn, fmt.Errorf("endpoint: %v", err)
		}
		if n.ACLSave || n.ManagedMarker != "" {
			return rn, errors.New("acl_save and managed_marker are only valid for redis")
		}
	case "redis":
		if n.Endpoint != nil || len(n.Servers) == 0 {
			return rn, errors.New("servers (and not endpoint) is required")
		}
		for i, s := range n.Servers {
			e, err := s.Resolve(allowPlain)
			if err != nil {
				return rn, fmt.Errorf("servers[%d]: %v", i, err)
			}
			rn.Servers = append(rn.Servers, e)
		}
		if n.Connect.Database != "" {
			return rn, errors.New("connect.database is not used for redis")
		}
	default:
		return rn, fmt.Errorf("unknown type %q (postgres, mysql, redis)", n.Type)
	}

	switch n.Type {
	case "postgres":
		if n.ManagedGroup == "" {
			return rn, errors.New("managed_group is required")
		}
		if n.ManagedRole != "" || n.AccountHost != "" {
			return rn, errors.New("managed_role/account_host are for mysql")
		}
	case "mysql":
		if n.ManagedRole == "" {
			return rn, errors.New("managed_role is required")
		}
		if n.ManagedGroup != "" {
			return rn, errors.New("managed_group is for postgres")
		}
	case "redis":
		if n.ManagedGroup != "" || n.ManagedRole != "" {
			return rn, errors.New("redis has no managed group/role")
		}
	}
	return rn, nil
}

// ReadEd25519PublicKey reads a PEM ("PUBLIC KEY", PKIX) Ed25519 public
// key.
func ReadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected exactly one PEM PUBLIC KEY block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return pk, nil
}

// ReadEd25519PrivateKey reads a PEM ("PRIVATE KEY", PKCS #8) Ed25519
// private key, applying secret-file permission checks.
func ReadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	v, err := secret.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(v.Bytes())
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected exactly one PEM PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	sk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return sk, nil
}
