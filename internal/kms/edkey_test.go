package kms

import (
	"crypto/ed25519"
	"testing"
)

func TestCheckEd25519PublicKey(t *testing.T) {
	pk, _, _ := ed25519.GenerateKey(nil)
	if err := CheckEd25519PublicKey(pk); err != nil {
		t.Fatalf("good key: %v", err)
	}
	identity := make([]byte, 32)
	identity[0] = 1
	bad := map[string][]byte{
		"identity": identity,
		"zero":     make([]byte, 32), // small order (order 4)
		"short":    make([]byte, 31),
		"y >= p":   append([]byte{0xee}, repeat(0xff, 30, 0x7f)...), // non-canonical
	}
	for name, k := range bad {
		if err := CheckEd25519PublicKey(k); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// The forgery the check prevents: with the identity key, (R=identity,
	// s=0) verifies for ANY message under Go's ed25519.Verify.
	sig := append(append([]byte(nil), identity...), make([]byte, 32)...)
	if !ed25519.Verify(identity, []byte("any message"), sig) {
		t.Skip("Go's Verify rejects small-order keys now; check still useful")
	}
}

func repeat(b byte, n int, last byte) []byte {
	out := make([]byte, n+1)
	for i := 0; i < n; i++ {
		out[i] = b
	}
	out[n] = last
	return out
}
