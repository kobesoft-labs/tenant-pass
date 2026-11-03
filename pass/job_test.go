package pass

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func jobSetup() (Signer, *JobVerifier) {
	sk := fixedKey(3)
	return Signer{KeyID: "jobs1", Key: sk}, &JobVerifier{
		Keys: map[string]ed25519.PublicKey{"jobs1": sk.Public().(ed25519.PublicKey)},
		Now:  func() time.Time { return t0.Add(time.Minute) },
	}
}

func jobClaims() JobClaims {
	return JobClaims{Audience: "billing", Tenant: "acme", IssuedAt: t0, Expiry: t0.Add(30 * time.Minute)}
}

func TestJobRoundTrip(t *testing.T) {
	s, v := jobSetup()
	tk, err := s.SignJob(context.Background(), jobClaims())
	if err != nil {
		t.Fatal(err)
	}
	c, kid, err := v.Verify(tk, "billing")
	if err != nil || c.Tenant != "acme" || kid != "jobs1" {
		t.Fatalf("%+v %s %v", c, kid, err)
	}
	if _, _, err := v.Verify(tk, "crm"); !errors.Is(err, ErrAudience) {
		t.Errorf("audience: %v", err)
	}
}

// A ticket is never a pass and a pass is never a ticket, even under the
// same key (different implicit assertions).
func TestJobAndPassAreSeparate(t *testing.T) {
	s, jv := jobSetup()
	tk, _ := s.SignJob(context.Background(), jobClaims())
	pv := &Verifier{Keys: jv.Keys, Now: jv.Now}
	if _, err := pv.Verify(tk, "billing"); !errors.Is(err, ErrSignature) {
		t.Errorf("ticket accepted as pass: %v", err)
	}
	p, _ := s.Sign(Claims{Audience: "billing", Tenant: "acme", IssuedAt: t0, Expiry: t0.Add(80 * time.Second)})
	if _, _, err := jv.Verify(p, "billing"); !errors.Is(err, ErrSignature) {
		t.Errorf("pass accepted as ticket: %v", err)
	}
}

func TestJobLimits(t *testing.T) {
	s, v := jobSetup()
	c := jobClaims()
	c.Expiry = t0.Add(2 * time.Hour) // over the default 1h
	tk, err := s.SignJob(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Verify(tk, "billing"); !errors.Is(err, ErrClaims) {
		t.Errorf("over max_ttl: %v", err)
	}
	c.Expiry = t0.Add(25 * time.Hour)
	if _, err := s.SignJob(context.Background(), c); err == nil {
		t.Error("signer accepted > 24h")
	}
	v.Now = func() time.Time { return t0.Add(31 * time.Minute) }
	tk, _ = s.SignJob(context.Background(), jobClaims())
	if _, _, err := v.Verify(tk, "billing"); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: %v", err)
	}
}

func TestRemoteSigner(t *testing.T) {
	sk := fixedKey(4)
	calls := 0
	s := Signer{KeyID: "remote", Remote: func(_ context.Context, msg []byte) ([]byte, error) {
		calls++
		return ed25519.Sign(sk, msg), nil
	}}
	tk, err := s.SignJob(context.Background(), jobClaims())
	if err != nil || calls != 1 {
		t.Fatal(err)
	}
	v := &JobVerifier{Keys: map[string]ed25519.PublicKey{"remote": sk.Public().(ed25519.PublicKey)}, Now: func() time.Time { return t0 }}
	if _, _, err := v.Verify(tk, "billing"); err != nil {
		t.Fatal(err)
	}
	if _, err := (Signer{KeyID: "x", Key: sk, Remote: s.Remote}).Sign(goodClaims()); err == nil {
		t.Error("both Key and Remote accepted")
	}
	bad := Signer{KeyID: "x", Remote: func(context.Context, []byte) ([]byte, error) { return []byte("short"), nil }}
	if _, err := bad.Sign(goodClaims()); err == nil {
		t.Error("short remote signature accepted")
	}
}

func FuzzJobVerify(f *testing.F) {
	s, v := jobSetup()
	// Fixed jti: fuzz workers run in separate processes and must all
	// derive the same seed ticket (Ed25519 signing is deterministic).
	c := jobClaims()
	c.ID = "AAAAAAAAAAAAAAAAAAAAAA"
	good, _ := s.SignJob(context.Background(), c)
	f.Add(good)
	f.Fuzz(func(t *testing.T, tk string) {
		if c, _, err := v.Verify(tk, "billing"); err == nil && tk != good {
			t.Fatalf("accepted fuzzed ticket %q: %+v", tk, c)
		}
	})
}
