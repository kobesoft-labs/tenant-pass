package kms

// Integration tests against a real OpenBao/Vault dev server. They run
// only when TENANT_PASS_TEST_VAULT is set to its address (for example
// http://127.0.0.1:58200) and its root token is "root" (see
// scripts/integration.sh).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func vaultAdmin(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()
	addr := os.Getenv("TENANT_PASS_TEST_VAULT")
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, addr+"/v1/"+path, rd)
	req.Header.Set("X-Vault-Token", "root")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 300 && !strings.Contains(path, "sys/mounts") {
		t.Fatalf("%s %s: HTTP %d %v", method, path, resp.StatusCode, out)
	}
	return out
}

func testVault(t *testing.T) *Vault {
	t.Helper()
	addr := os.Getenv("TENANT_PASS_TEST_VAULT")
	if addr == "" {
		t.Skip("TENANT_PASS_TEST_VAULT not set")
	}
	vaultAdmin(t, "POST", "sys/mounts/transit", map[string]any{"type": "transit"})
	tok := t.TempDir() + "/token"
	if err := os.WriteFile(tok, []byte("root\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := NewVault(VaultConfig{Address: addr, TokenFile: tok})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Transit's HMAC must be plain HMAC-SHA256 with the key material, so the
// derivation specification holds whether keys are local or remote.
func TestIntegrationTransitMACMatchesLocal(t *testing.T) {
	v := testVault(t)
	vaultAdmin(t, "POST", "transit/keys/tp-test-hmac", map[string]any{"type": "hmac", "key_size": 32, "exportable": true})
	exp := vaultAdmin(t, "GET", "transit/export/hmac-key/tp-test-hmac/1", nil)
	keyB64 := exp["data"].(map[string]any)["keys"].(map[string]any)["1"].(string)
	key, _ := base64.StdEncoding.DecodeString(keyB64)

	m, err := v.NewTransitMAC("tp-test-hmac", 1)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("tenant-pass/v1/password\x00\x00\x00\x08postgres")
	got, err := m.MAC(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	if !hmac.Equal(got, h.Sum(nil)) {
		t.Fatal("transit HMAC differs from local HMAC-SHA256")
	}

	// A key version that does not exist fails instead of silently
	// using another version.
	m2, _ := v.NewTransitMAC("tp-test-hmac", 9)
	if _, err := m2.MAC(context.Background(), msg); err == nil {
		t.Fatal("missing key version accepted")
	}
}

func TestIntegrationTransitSigner(t *testing.T) {
	v := testVault(t)
	vaultAdmin(t, "POST", "transit/keys/tp-test-ed", map[string]any{"type": "ed25519"})
	s, err := v.NewTransitSigner(context.Background(), "tp-test-ed", 1)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(s.Public(), []byte("hello"), sig) {
		t.Fatal("signature does not verify")
	}
	// A non-Ed25519 key is refused.
	if _, err := v.NewTransitSigner(context.Background(), "tp-test-hmac-x", 1); err == nil {
		t.Fatal("missing key accepted")
	}
}

func TestIntegrationBadToken(t *testing.T) {
	v := testVault(t)
	if err := os.WriteFile(v.cfg.TokenFile, []byte("wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ := v.NewTransitMAC("tp-test-hmac", 1)
	_, err := m.MAC(context.Background(), []byte("x"))
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("err = %v", err)
	}
}
