package kms

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"os"
	"testing"
)

func TestLocal(t *testing.T) {
	m := NewLocalMAC([]byte("k"))
	a, _ := m.MAC(context.Background(), []byte("x"))
	b, _ := NewLocalMAC([]byte("k")).MAC(context.Background(), []byte("x"))
	if string(a) != string(b) || m.Fingerprint() == NewLocalMAC([]byte("j")).Fingerprint() {
		t.Fatal("local MAC")
	}
	_, sk, _ := ed25519.GenerateKey(nil)
	s, _ := NewLocalSigner(sk)
	sig, _ := s.Sign(context.Background(), []byte("m"))
	if !ed25519.Verify(s.Public(), []byte("m"), sig) {
		t.Fatal("local signer")
	}
}

func TestNewVaultValidation(t *testing.T) {
	tok := t.TempDir() + "/t"
	writeFile(t, tok, "x")
	bad := []VaultConfig{
		{Address: "https://vault:8200", TokenFile: tok},                        // https without TLS config
		{Address: "http://vault:8200", TokenFile: tok, TLS: &tls.Config{}},     // http with TLS
		{Address: "https://vault:8200/v1", TokenFile: tok, TLS: &tls.Config{}}, // path
		{Address: "https://u:p@vault:8200", TokenFile: tok, TLS: &tls.Config{}},
		{Address: "https://vault:8200", TLS: &tls.Config{}}, // no token
		{Address: "https://vault:8200", TokenFile: tok, TLS: &tls.Config{}, Mount: "../sys"},
	}
	for i, c := range bad {
		if _, err := NewVault(c); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := NewVault(VaultConfig{Address: "https://vault:8200", TokenFile: tok, TLS: &tls.Config{}, Mount: "kms/transit"}); err != nil {
		t.Error(err)
	}
}

func TestParseVaultValue(t *testing.T) {
	if _, err := parseVaultValue("vault:v2:AAAA", 1); err == nil {
		t.Error("wrong version accepted")
	}
	if b, err := parseVaultValue("vault:v1:AAAA", 1); err != nil || len(b) != 3 {
		t.Error(err)
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
