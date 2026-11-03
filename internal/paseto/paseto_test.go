package paseto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Official PASETO v4 test vectors, copied from
// https://github.com/paseto-standard/test-vectors (v4.json).
// All 4-S vectors share one key pair.
const (
	vecPublicKeyHex = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
	vecSeedHex      = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774"
	vecPayload      = `{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}`
	vecFooter       = `{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`
)

var vectors = []struct {
	name, token, footer, assertion string
}{
	{
		name:  "4-S-1",
		token: "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA",
	},
	{
		name:   "4-S-2",
		token:  "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
		footer: vecFooter,
	},
	{
		name:      "4-S-3",
		token:     "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
		footer:    vecFooter,
		assertion: `{"test-vector":"4-S-3"}`,
	},
}

func vecKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, err := hex.DecodeString(vecPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vecSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	sk := ed25519.NewKeyFromSeed(seed)
	if !sk.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pub)) {
		t.Fatal("test vector seed does not match public key")
	}
	return pub, sk
}

func TestOfficialVectorsVerify(t *testing.T) {
	pub, _ := vecKeys(t)
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			m, f, err := Verify(pub, v.token, []byte(v.assertion))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if string(m) != vecPayload {
				t.Errorf("message = %q", m)
			}
			if string(f) != v.footer {
				t.Errorf("footer = %q, want %q", f, v.footer)
			}
		})
	}
}

// Ed25519 is deterministic, so signing must reproduce the vectors exactly.
func TestOfficialVectorsSign(t *testing.T) {
	_, sk := vecKeys(t)
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := Sign(sk, []byte(vecPayload), []byte(v.footer), []byte(v.assertion))
			if err != nil {
				t.Fatal(err)
			}
			if got != v.token {
				t.Errorf("Sign mismatch\n got %s\nwant %s", got, v.token)
			}
		})
	}
}

// 4-F-1 from the official vectors: a v4.local token must be rejected by a
// v4.public verifier.
func TestOfficialFailureVectorLocalHeader(t *testing.T) {
	pub, _ := vecKeys(t)
	tok := "v4.local.vngXfCISbnKgiP6VWGuOSlYrFYU300fy9ijW33rznDYgxHNPwWluAY2Bgb0z54CUs6aYYkIJ-bOOOmJHPuX_34Agt_IPlNdGDpRdGNnBz2MpWJvB3cttheEc1uyCEYltj7wBQQYX.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24"
	if _, _, err := Verify(pub, tok, []byte(`{"test-vector":"4-F-1"}`)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestWrongAssertionOrKeyFails(t *testing.T) {
	pub, _ := vecKeys(t)
	v := vectors[2]
	if _, _, err := Verify(pub, v.token, nil); !errors.Is(err, ErrSignature) {
		t.Errorf("missing assertion: err = %v", err)
	}
	if _, _, err := Verify(pub, v.token, []byte(`{"test-vector":"other"}`)); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong assertion: err = %v", err)
	}
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, _, err := Verify(otherPub, v.token, []byte(v.assertion)); !errors.Is(err, ErrSignature) {
		t.Errorf("wrong key: err = %v", err)
	}
}

// Every single-character change anywhere in the token must be rejected.
func TestTamperingIsDetected(t *testing.T) {
	pub, _ := vecKeys(t)
	v := vectors[1]
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
	for pos := 0; pos < len(v.token); pos++ {
		for _, c := range []byte{alphabet[pos%len(alphabet)], 'A', '_'} {
			if v.token[pos] == c {
				continue
			}
			mut := v.token[:pos] + string(c) + v.token[pos+1:]
			if _, _, err := Verify(pub, mut, nil); err == nil {
				t.Fatalf("tampered token accepted (pos %d -> %q)", pos, c)
			}
		}
	}
}

func TestMalformedInputs(t *testing.T) {
	pub, _ := vecKeys(t)
	good := vectors[1].token
	body := strings.TrimPrefix(strings.SplitN(good, ".", 4)[2], "")
	cases := map[string]string{
		"empty":            "",
		"v3 header":        "v3.public." + body,
		"uppercase header": "V4.PUBLIC." + body,
		"no body":          "v4.public.",
		"short body":       "v4.public.AAAA",
		"empty footer":     "v4.public." + body + ".",
		"two footers":      good + ".eyJ9",
		"padding":          "v4.public." + body + "==",
		"std alphabet":     "v4.public." + strings.ReplaceAll(body, "_", "/"),
		"too long":         "v4.public." + strings.Repeat("A", MaxTokenLength),
		"embedded newline": "v4.public." + body[:10] + "\n" + body[10:],
		"embedded CR":      "v4.public." + body[:10] + "\r" + body[10:],
		"embedded space":   "v4.public." + body[:10] + " " + body[10:],
	}
	for name, tok := range cases {
		if _, _, err := Verify(pub, tok, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Non-canonical base64 (non-zero unused trailing bits) must be rejected
// so a token has exactly one textual form.
func TestNonCanonicalBase64Rejected(t *testing.T) {
	pub, sk := vecKeys(t)
	tok, err := Sign(sk, []byte("x"), nil, nil) // 65 bytes -> 87 chars, 2 spare bits
	if err != nil {
		t.Fatal(err)
	}
	last := tok[len(tok)-1]
	idx := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", last)
	alt := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[idx^1]
	mut := tok[:len(tok)-1] + string(alt)
	if _, _, err := Verify(pub, mut, nil); err == nil {
		t.Fatal("non-canonical base64 accepted")
	}
}

func TestFooterIsUnverified(t *testing.T) {
	f, err := Footer(vectors[1].token)
	if err != nil || string(f) != vecFooter {
		t.Fatalf("Footer = %q, %v", f, err)
	}
	f, err = Footer(vectors[0].token)
	if err != nil || f != nil {
		t.Fatalf("Footer (none) = %q, %v", f, err)
	}
}

func FuzzVerify(f *testing.F) {
	for _, v := range vectors {
		f.Add(v.token)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	f.Fuzz(func(t *testing.T, tok string) {
		m, _, err := Verify(pub, tok, nil)
		if err == nil {
			t.Fatalf("random key verified fuzzed token: %q", m)
		}
	})
}
