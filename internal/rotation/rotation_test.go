package rotation

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/kms"
)

func testSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func testSchedule(t *testing.T) *Schedule {
	t.Helper()
	s, err := NewSchedule(15*time.Minute, 5*time.Minute, []Key{{ID: "k1", MAC: kms.NewLocalMAC(testSecret()), NotBefore: time.Unix(0, 0)}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Vectors produced by the independent reference implementation in
// scripts/derivation_vectors.py (and published in docs/en/derivation.md).
func TestVectors(t *testing.T) {
	s := testSchedule(t)
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		acc      Account
		start    int64
		password string
		salt     string
	}{
		{Account{"postgres", "pg1", "t_acme"}, 1793706839, "lRG6msAkg88kIIjJU-N6yWZ6wzx1gQj62GYG71hcgjE", "abf9ab9a389f481fee4908dd172c9cccbadfec535752012f6409fd656d729d1a"},
		{Account{"mysql", "my1", "t_acme"}, 1793706901, "e1J8ptbuAhJdMRKoN64HY-aPS_M_8qT5JBYJPCuixDg", "b810862d689e69fa9b9e7505734ead2377cc468d2c81eeb6f48c7fc2556b8034"},
		{Account{"redis", "rd1", "t_acme"}, 1793706386, "10MHE6qMKh6XzzFzHwmXBvgWoezTwvsUYb91z3guUHc", "51ffc4190e3dc0774a7711bf75a433650b3d7d0235b8c879ec569274e11ff1b5"},
	}
	for _, c := range cases {
		n := s.Index(c.acc, now)
		if n != 1993007 {
			t.Errorf("%v: index = %d", c.acc, n)
		}
		if got := s.Start(c.acc, n).Unix(); got != c.start {
			t.Errorf("%v: start = %d, want %d", c.acc, got, c.start)
		}
		pw, kid, err := s.Password(context.Background(), c.acc, n)
		if err != nil || pw != c.password || kid != "k1" {
			t.Errorf("%v: password = %q %q %v", c.acc, pw, kid, err)
		}
		salt, _ := s.Salt(context.Background(), c.acc, n)
		if hex.EncodeToString(salt) != c.salt {
			t.Errorf("%v: salt = %x", c.acc, salt)
		}
	}
}

func TestWindowsAndTarget(t *testing.T) {
	s := testSchedule(t)
	a := Account{"postgres", "pg1", "t_acme"}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	n := s.Index(a, now)
	start, end := s.Start(a, n), s.End(a, n)
	if now.Before(start) || !now.Before(end) || end.Sub(start) != 15*time.Minute {
		t.Fatalf("window [%v, %v) does not contain %v", start, end, now)
	}
	if got := s.Index(a, end.Add(-time.Nanosecond)); got != n {
		t.Errorf("just before end: %d", got)
	}
	if got := s.Index(a, end); got != n+1 {
		t.Errorf("at end: %d", got)
	}
	// Target switches exactly at End - RenewBefore.
	if got := s.Target(a, end.Add(-5*time.Minute-time.Second)); got != n {
		t.Errorf("before renew: %d", got)
	}
	if got := s.Target(a, end.Add(-5*time.Minute)); got != n+1 {
		t.Errorf("at renew: %d", got)
	}
	if got := s.RefreshAt(a, n); !got.Equal(end.Add(-5 * time.Minute)) {
		t.Errorf("RefreshAt = %v", got)
	}
	// IndexOfEnd recognizes exactly the boundaries of this account.
	if k, ok := s.IndexOfEnd(a, end); !ok || k != n {
		t.Errorf("IndexOfEnd(end) = %d %v", k, ok)
	}
	if _, ok := s.IndexOfEnd(a, end.Add(time.Second)); ok {
		t.Error("IndexOfEnd accepted a misaligned time")
	}
	if _, ok := s.IndexOfEnd(a, end.Add(time.Microsecond)); ok {
		t.Error("IndexOfEnd accepted sub-second time")
	}
}

// Every credential handed out must be valid for at least RenewBefore.
func TestMinimumValidity(t *testing.T) {
	s := testSchedule(t)
	a := Account{"redis", "r", "u"}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 2000; i++ {
		now := base.Add(time.Duration(i) * 7 * time.Second)
		n := s.Target(a, now)
		if left := s.End(a, n).Sub(now); left < s.RenewBefore || left > s.Window+s.RenewBefore {
			t.Fatalf("at %v: %v left", now, left)
		}
	}
}

func TestOffsetsDiffer(t *testing.T) {
	s := testSchedule(t)
	seen := map[int64]int{}
	for i := 0; i < 50; i++ {
		seen[s.offset(Account{"postgres", "pg1", "t" + string(rune('a'+i%26)) + string(rune('a'+i/26))})]++
	}
	if len(seen) < 40 {
		t.Errorf("offsets are not spread: %d distinct of 50", len(seen))
	}
}

func TestDomainSeparation(t *testing.T) {
	s := testSchedule(t)
	n := int64(100)
	p1, _, _ := s.Password(context.Background(), Account{"postgres", "n", "u"}, n)
	p2, _, _ := s.Password(context.Background(), Account{"mysql", "n", "u"}, n)
	p3, _, _ := s.Password(context.Background(), Account{"postgres", "n", "u"}, n+1)
	// Length prefixes: ("ab","c") must differ from ("a","bc").
	p4, _, _ := s.Password(context.Background(), Account{"postgres", "ab", "c"}, n)
	p5, _, _ := s.Password(context.Background(), Account{"postgres", "a", "bc"}, n)
	if p1 == p2 || p1 == p3 || p4 == p5 {
		t.Fatal("derivation inputs are not separated")
	}
}

// Changing the window length must never make a new window reuse an old
// window's password (window numbers collide across lengths).
func TestWindowLengthInDerivation(t *testing.T) {
	a := Account{"postgres", "pg1", "t"}
	s1, _ := NewSchedule(15*time.Minute, 5*time.Minute, []Key{{ID: "k1", MAC: kms.NewLocalMAC(testSecret())}})
	s2, _ := NewSchedule(16*time.Minute, 5*time.Minute, []Key{{ID: "k1", MAC: kms.NewLocalMAC(testSecret())}})
	p1, _, _ := s1.Password(context.Background(), a, 1000)
	p2, _, _ := s2.Password(context.Background(), a, 1000)
	if p1 == p2 {
		t.Fatal("same window number under different lengths gives the same password")
	}
}

func TestKeyRotation(t *testing.T) {
	switchAt := time.Date(2026, 12, 1, 3, 0, 0, 0, time.UTC)
	k2 := make([]byte, 32)
	k2[0] = 0xff
	s, err := NewSchedule(15*time.Minute, 5*time.Minute, []Key{
		{ID: "k2", MAC: kms.NewLocalMAC(k2), NotBefore: switchAt},
		{ID: "k1", MAC: kms.NewLocalMAC(testSecret()), NotBefore: time.Unix(0, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := Account{"postgres", "pg1", "t_acme"}
	n := s.Index(a, switchAt)
	// The window that contains switchAt started before it: still k1.
	if _, kid, _ := s.Password(context.Background(), a, n); kid != "k1" {
		t.Errorf("window containing switch uses %s", kid)
	}
	// The first window starting at or after switchAt uses k2.
	if _, kid, _ := s.Password(context.Background(), a, n+1); kid != "k2" {
		t.Errorf("next window uses %s", kid)
	}
}

func TestNewScheduleValidation(t *testing.T) {
	good := []Key{{ID: "k1", MAC: kms.NewLocalMAC(testSecret())}}
	bad := []struct {
		name       string
		window, rb time.Duration
		keys       []Key
	}{
		{"short window", 30 * time.Second, 10 * time.Second, good},
		{"fractional window", 90*time.Second + time.Millisecond, 10 * time.Second, good},
		{"renew too big", 10 * time.Minute, 6 * time.Minute, good},
		{"renew zero", 10 * time.Minute, 0, good},
		{"no keys", 10 * time.Minute, time.Minute, nil},
		{"no key material", 10 * time.Minute, time.Minute, []Key{{ID: "k", MAC: nil}}},
		{"dup id", 10 * time.Minute, time.Minute, []Key{{ID: "k", MAC: kms.NewLocalMAC(testSecret())}, {ID: "k", MAC: kms.NewLocalMAC(make([]byte, 32)), NotBefore: time.Unix(1, 0)}}},
		{"dup secret", 10 * time.Minute, time.Minute, []Key{{ID: "a", MAC: kms.NewLocalMAC(testSecret())}, {ID: "b", MAC: kms.NewLocalMAC(testSecret()), NotBefore: time.Unix(1, 0)}}},
		{"same not_before", 10 * time.Minute, time.Minute, []Key{{ID: "a", MAC: kms.NewLocalMAC(testSecret())}, {ID: "b", MAC: kms.NewLocalMAC(make([]byte, 32))}}},
	}
	for _, b := range bad {
		if _, err := NewSchedule(b.window, b.rb, b.keys); err == nil {
			t.Errorf("%s: accepted", b.name)
		}
	}
}

func TestCheckCurrentKey(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	s, _ := NewSchedule(15*time.Minute, 5*time.Minute, []Key{{ID: "k1", MAC: kms.NewLocalMAC(testSecret()), NotBefore: now.Add(time.Hour)}})
	if err := s.CheckCurrentKey(now); err == nil {
		t.Error("future-only key accepted")
	}
	s, _ = NewSchedule(15*time.Minute, 5*time.Minute, []Key{{ID: "k1", MAC: kms.NewLocalMAC(testSecret()), NotBefore: now.Add(-time.Hour)}})
	if err := s.CheckCurrentKey(now); err != nil {
		t.Error(err)
	}
}
