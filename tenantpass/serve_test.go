package tenantpass

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServeWithExtension starts the real server from a configuration file
// and checks that an extension's routes are served on the same listener,
// with the core's security headers, next to the core routes, and that
// Serve returns cleanly when ctx is cancelled.
func TestServeWithExtension(t *testing.T) {
	dir := t.TempDir()
	w := func(name, content string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	pk, _, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKIXPublicKey(pk)
	w("gw.pub", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), 0o644)
	w("rot.key", "pQ4m0g2Yk3qvQW1o8bqgK3n4cS1u9xJ0eF7rT6yU5iA=\n", 0o600)
	w("pg.pw", "adminpw\n", 0o600)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg := `{
  "listen": "ADDR",
  "allow_insecure_plaintext": true,
  "insecure_plaintext_http": true,
  "gateway_keys": [{"id": "gw1", "public_key_file": "DIR/gw.pub"}],
  "apps": [{"name": "billing", "token_sha256": "0b3f8f1f8f4a3c8d7e6b5a4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e"}],
  "directory": {"static": {"tenants": [
    {"id": "acme", "hosts": ["acme.example.com"], "node": "pg1", "account": "t_acme", "enabled": true, "apps": ["billing"]}
  ]}},
  "rotation": {"keys": [{"id": "k1", "secret_file": "DIR/rot.key", "not_before": "2020-01-01T00:00:00Z"}]},
  "nodes": [{
    "name": "pg1", "type": "postgres",
    "endpoint": {"address": "127.0.0.1:1", "user": "tenant_pass_admin", "password_file": "DIR/pg.pw", "database": "tenant_pass", "insecure_plaintext": true},
    "managed_group": "tenant_pass_managed", "account_pattern": "^t_[a-z0-9_]+$",
    "connect": {"host": "pgbouncer.internal", "port": 6432, "database": "app"}
  }],
  "shutdown": {"drain": "0s", "timeout": "2s"}
}`
	cfg = strings.NewReplacer("DIR", dir, "ADDR", addr).Replace(cfg)
	w("config.json", cfg, 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, Options{
			ConfigPath: filepath.Join(dir, "config.json"),
			Extensions: []Extension{{
				Name: "legacy",
				Mount: func(context.Context, Host) (map[string]http.Handler, error) {
					return map[string]http.Handler{"POST /v1/legacy": http.HandlerFunc(ok)}, nil
				},
				Close: func() { close(closed) },
			}},
		})
	}()

	var res *http.Response
	for i := 0; i < 100; i++ {
		res, err = http.Post("http://"+addr+"/v1/legacy", "application/json", strings.NewReader("{}"))
		if err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Serve returned early: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusTeapot || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("extension route: %d %q", res.StatusCode, res.Header.Get("Cache-Control"))
	}
	// A core route is still the core's.
	res, err = http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %d", res.StatusCode)
	}
	// Unknown paths are still 404.
	res, err = http.Post("http://"+addr+"/v1/other", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path: %d", res.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
	select {
	case <-closed:
	default:
		t.Fatal("extension Close was not called")
	}
}
