package pass

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/paseto"
)

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func fixedKey(seedByte byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	return ed25519.NewKeyFromSeed(seed)
}

func setup() (Signer, *Verifier) {
	sk := fixedKey(1)
	s := Signer{KeyID: "gw1", Key: sk}
	v := &Verifier{
		Keys: map[string]ed25519.PublicKey{"gw1": sk.Public().(ed25519.PublicKey)},
		Now:  func() time.Time { return t0.Add(10 * time.Second) },
	}
	return s, v
}

func goodClaims() Claims {
	return Claims{Audience: "billing", Host: "acme.example.com", IssuedAt: t0, Expiry: t0.Add(30 * time.Second), ID: "AAAAAAAAAAAAAAAAAAAAAA"}
}

func TestRoundTrip(t *testing.T) {
	s, v := setup()
	p, err := s.Sign(goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(p, "billing")
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "acme.example.com" || c.Audience != "billing" || !c.Expiry.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("claims = %+v", c)
	}
}

// Test vector published in docs/en/pass-format.md. If this changes, the
// documentation (and every independent implementation) must change too.
func TestPublishedVector(t *testing.T) {
	s, v := setup()
	p, err := s.Sign(goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	// Signing key: Ed25519 seed of 32 bytes 0x01, key ID "gw1".
	const want = "v4.public.eyJhdWQiOiJiaWxsaW5nIiwiaG9zdCI6ImFjbWUuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDI2LTExLTAzVDEyOjAwOjAwWiIsImV4cCI6IjIwMjYtMTEtMDNUMTI6MDA6MzBaIiwianRpIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSJ9lGRulfEQdJnx_Iagf4Fp94_8eSIifNPHT82HGA8KqWhSX_KikCQafPjF2Ntupw3XnYtRoZ6xe1-uf46uZcHoDQ.eyJraWQiOiJndzEifQ"
	if p != want {
		t.Fatalf("pass vector changed:\n%s", p)
	}
	t.Logf("vector: %s", p)
	if _, err := v.Verify(p, "billing"); err != nil {
		t.Fatal(err)
	}
}

func TestTenantClaim(t *testing.T) {
	s, v := setup()
	c := goodClaims()
	c.Host, c.Tenant = "", "acme"
	p, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(p, "billing")
	if err != nil || got.Tenant != "acme" || got.Host != "" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestVerifyFailures(t *testing.T) {
	s, v := setup()
	good, _ := s.Sign(goodClaims())

	expect := func(name string, p, aud string, want error) {
		t.Helper()
		if _, err := v.Verify(p, aud); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", name, err, want)
		}
	}
	expect("audience", good, "other", ErrAudience)

	other := Signer{KeyID: "gw1", Key: fixedKey(2)}
	forged, _ := other.Sign(goodClaims())
	expect("forged", forged, "billing", ErrSignature)

	unknown := Signer{KeyID: "gw9", Key: fixedKey(1)}
	u, _ := unknown.Sign(goodClaims())
	expect("unknown kid", u, "billing", ErrUnknownKey)

	vLate := *v
	vLate.Now = func() time.Time { return t0.Add(30 * time.Second) }
	if _, err := vLate.Verify(good, "billing"); !errors.Is(err, ErrExpired) {
		t.Errorf("at exp: %v", err)
	}
	vEarly := *v
	vEarly.Now = func() time.Time { return t0.Add(-6 * time.Second) }
	if _, err := vEarly.Verify(good, "billing"); !errors.Is(err, ErrExpired) {
		t.Errorf("iat in future: %v", err)
	}

	long := goodClaims()
	long.Expiry = t0.Add(61 * time.Second)
	lp, _ := s.Sign(long)
	expect("too long", lp, "billing", ErrClaims)

	expect("garbage", "v4.public.xxx", "billing", ErrMalformed)
	expect("no footer", strings.SplitN(good, ".", 4)[0]+"."+strings.SplitN(good, ".", 4)[1]+"."+strings.SplitN(good, ".", 4)[2], "billing", ErrMalformed)
	expect("oversize", good+strings.Repeat("A", MaxLength), "billing", ErrMalformed)
}

// Signs arbitrary raw claims JSON with a valid key, to test the schema
// checks that Signer itself would never violate.
func signRaw(t *testing.T, claims string) string {
	t.Helper()
	f, _ := json.Marshal(footer{Kid: "gw1"})
	p, err := paseto.Sign(fixedKey(1), []byte(claims), f, []byte(ImplicitAssertion))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSchemaStrictness(t *testing.T) {
	_, v := setup()
	base := `"aud":"billing","iat":"2026-11-03T12:00:00Z","exp":"2026-11-03T12:00:30Z","jti":"AAAAAAAAAAAAAAAAAAAAAA"`
	cases := map[string]string{
		"duplicate host":  `{` + base + `,"host":"acme.example.com","host":"evil.example.com"}`,
		"duplicate aud":   `{` + base + `,"host":"acme.example.com","aud":"billing"}`,
		"unknown claim":   `{` + base + `,"host":"acme.example.com","admin":true}`,
		"both":            `{` + base + `,"host":"acme.example.com","tenant":"acme"}`,
		"neither":         `{` + base + `}`,
		"upper host":      `{` + base + `,"host":"ACME.example.com"}`,
		"host with port":  `{` + base + `,"host":"acme.example.com:443"}`,
		"bad tenant":      `{` + base + `,"tenant":"../etc"}`,
		"non-UTC time":    `{"aud":"billing","iat":"2026-11-03T21:00:00+09:00","exp":"2026-11-03T12:00:30Z","jti":"AAAAAAAAAAAAAAAAAAAAAA","host":"acme.example.com"}`,
		"fractional time": `{"aud":"billing","iat":"2026-11-03T12:00:00.5Z","exp":"2026-11-03T12:00:30Z","jti":"AAAAAAAAAAAAAAAAAAAAAA","host":"acme.example.com"}`,
		"numeric time":    `{"aud":"billing","iat":1793707200,"exp":"2026-11-03T12:00:30Z","jti":"AAAAAAAAAAAAAAAAAAAAAA","host":"acme.example.com"}`,
		"short jti":       `{"aud":"billing","iat":"2026-11-03T12:00:00Z","exp":"2026-11-03T12:00:30Z","jti":"abc","host":"acme.example.com"}`,
		"exp before iat":  `{"aud":"billing","iat":"2026-11-03T12:00:30Z","exp":"2026-11-03T12:00:00Z","jti":"AAAAAAAAAAAAAAAAAAAAAA","host":"acme.example.com"}`,
		"array":           `["billing"]`,
	}
	for name, claims := range cases {
		if _, err := v.Verify(signRaw(t, claims), "billing"); !errors.Is(err, ErrClaims) {
			t.Errorf("%s: err = %v, want ErrClaims", name, err)
		}
	}
}

// A token signed by the gateway key for a different purpose (different
// implicit assertion) must not be accepted as a pass.
func TestDomainSeparation(t *testing.T) {
	_, v := setup()
	f, _ := json.Marshal(footer{Kid: "gw1"})
	m := `{"aud":"billing","host":"acme.example.com","iat":"2026-11-03T12:00:00Z","exp":"2026-11-03T12:00:30Z","jti":"AAAAAAAAAAAAAAAAAAAAAA"}`
	for _, ia := range []string{"", "tenant-pass/v1/other", "tenant-pass/v2/pass"} {
		p, _ := paseto.Sign(fixedKey(1), []byte(m), f, []byte(ia))
		if _, err := v.Verify(p, "billing"); !errors.Is(err, ErrSignature) {
			t.Errorf("assertion %q: err = %v", ia, err)
		}
	}
}

func FuzzVerify(f *testing.F) {
	s, v := setup()
	good, _ := s.Sign(goodClaims())
	f.Add(good)
	f.Fuzz(func(t *testing.T, p string) {
		c, err := v.Verify(p, "billing")
		if err == nil && p != good {
			// Any other accepted string must still be a correctly signed
			// pass; with a fixed key, the fuzzer cannot produce one.
			t.Fatalf("accepted fuzzed pass %q: %+v", p, c)
		}
	})
}
