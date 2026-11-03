package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixture writes a minimal valid configuration and its secret files into
// a temp dir, and returns the config path. mutate edits the JSON text.
func fixture(t *testing.T, mutate func(string) string) string {
	t.Helper()
	dir := t.TempDir()
	w := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pk, _, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKIXPublicKey(pk)
	w("gw.pub", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), 0o644)
	w("rot.key", "pQ4m0g2Yk3qvQW1o8bqgK3n4cS1u9xJ0eF7rT6yU5iA=\n", 0o600)
	w("pg.pw", "adminpw\n", 0o600)
	w("tls.key", "unused\n", 0o600)
	cfg := `{
  "listen": "127.0.0.1:8443",
  "tls": {"cert_file": "DIR/tls.crt", "key_file": "DIR/tls.key"},
  "gateway_keys": [{"id": "gw1", "public_key_file": "DIR/gw.pub"}],
  "apps": [{"name": "billing", "token_sha256": "0b3f8f1f8f4a3c8d7e6b5a4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"}],
  "directory": {"static": {"tenants": [
    {"id": "acme", "hosts": ["acme.example.com"], "node": "pg1", "account": "t_acme", "enabled": true, "apps": ["billing"]}
  ]}},
  "rotation": {"keys": [{"id": "k1", "secret_file": "DIR/rot.key", "not_before": "2020-01-01T00:00:00Z"}]},
  "nodes": [{
    "name": "pg1", "type": "postgres",
    "endpoint": {"address": "db.internal:5432", "user": "tenant_pass_admin", "password_file": "DIR/pg.pw"},
    "managed_group": "tenant_pass_managed", "account_pattern": "^t_[a-z0-9_]+$",
    "connect": {"host": "pgbouncer.internal", "port": 6432, "database": "app"}
  }]
}`
	if mutate != nil {
		cfg = mutate(cfg)
	}
	return w("config.json", strings.ReplaceAll(cfg, "DIR", dir), 0o600)
}

func load(t *testing.T, mutate func(string) string) (*Resolved, error) {
	t.Helper()
	f, err := Load(fixture(t, mutate))
	if err != nil {
		return nil, err
	}
	return Resolve(f, time.Now())
}

func TestValidConfig(t *testing.T) {
	r, err := load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Schedule.Window != 15*time.Minute || len(r.Nodes) != 1 || r.Nodes[0].Endpoint.TLS == nil {
		t.Fatalf("unexpected resolution: %+v", r)
	}
	if r.Nodes[0].Endpoint.TLS.InsecureSkipVerify || r.Nodes[0].Endpoint.TLS.ServerName != "db.internal" {
		t.Fatal("store TLS must verify the server name")
	}
}

func TestInvalidConfigs(t *testing.T) {
	rep := func(old, new string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				t.Fatalf("fixture does not contain %q", old)
			}
			return strings.Replace(s, old, new, 1)
		}
	}
	cases := map[string]func(string) string{
		"unknown key":            rep(`"listen"`, `"listen_addr": "x", "listen"`),
		"duplicate key":          rep(`"listen": "127.0.0.1:8443",`, `"listen": "127.0.0.1:8443", "listen": "0.0.0.0:8443",`),
		"plaintext http alone":   rep(`"tls": {"cert_file": "DIR/tls.crt", "key_file": "DIR/tls.key"},`, `"insecure_plaintext_http": true,`),
		"plaintext db alone":     rep(`"password_file": "DIR/pg.pw"}`, `"password_file": "DIR/pg.pw", "insecure_plaintext": true}`),
		"no tls":                 rep(`"tls": {"cert_file": "DIR/tls.crt", "key_file": "DIR/tls.key"},`, ``),
		"unanchored pattern":     rep(`"^t_[a-z0-9_]+$"`, `"t_[a-z0-9_]+"`),
		"no managed group":       rep(`"managed_group": "tenant_pass_managed",`, ``),
		"uppercase token hash":   rep(`0b3f8f1f`, `0B3F8F1F`),
		"short token hash":       rep(`0b3f8f1f8f4a`, `0b3f`),
		"unknown node in tenant": rep(`"node": "pg1", "account"`, `"node": "pg9", "account"`),
		"unknown app in tenant":  rep(`"apps": ["billing"]`, `"apps": ["crm"]`),
		"future-only key":        rep(`2020-01-01T00:00:00Z`, `2999-01-01T00:00:00Z`),
		"missing key file":       rep(`DIR/rot.key`, `DIR/nope.key`),
		"bad type":               rep(`"type": "postgres"`, `"type": "oracle"`),
		"window too short":       rep(`"rotation": {`, `"rotation": {"window": "30s", `),
		"max_ttl too long":       rep(`"apps":`, `"pass": {"max_ttl": "10m"}, "apps":`),
		"cert uri without ca":    rep(`"token_sha256"`, `"client_cert_uri": "spiffe://x/y", "token_sha256"`),
		"both directories":       rep(`"directory": {`, `"directory": {"sql": {"driver": "postgres"}, `),
		"redis with endpoint":    rep(`"type": "postgres"`, `"type": "redis"`),
		"bad log level":          rep(`"listen"`, `"log_level": "verbose", "listen"`),
	}
	for name, mut := range cases {
		if _, err := load(t, mut); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Alternation must not escape the anchors.
func TestAccountPatternFullyAnchored(t *testing.T) {
	r, err := load(t, func(s string) string {
		return strings.Replace(s, `"^t_[a-z0-9_]+$"`, `"^t_[a-z]+|svc$"`, 1)
	})
	if err != nil {
		t.Fatal(err)
	}
	re := r.Nodes[0].AccountPattern
	for _, name := range []string{"t_acme_admin!", "x_svc", "t_acme-x"} {
		if re.MatchString(name) {
			t.Errorf("%q matched", name)
		}
	}
	if !re.MatchString("t_acme") || !re.MatchString("svc") {
		t.Error("intended names do not match")
	}
}

// The shipped example must at least parse.
func TestExampleConfigParses(t *testing.T) {
	if _, err := Load("../../examples/config.example.json"); err != nil {
		t.Fatal(err)
	}
}

func TestConfigFilePermissions(t *testing.T) {
	p := fixture(t, nil)
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("world-writable config accepted")
	}
}
