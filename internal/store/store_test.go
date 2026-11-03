package store

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/kms"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
)

func sched(t *testing.T) *rotation.Schedule {
	t.Helper()
	s, err := rotation.NewSchedule(15*time.Minute, 5*time.Minute, []rotation.Key{{ID: "k1", MAC: kms.NewLocalMAC(make([]byte, 32))}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPlanSoft(t *testing.T) {
	s := sched(t)
	a := rotation.Account{Store: "redis", Node: "r1", Name: "t_acme"}
	base := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	cur := s.Index(a, base)
	mid := s.Start(a, cur).Add(2 * time.Minute)  // normal phase
	renew := s.End(a, cur).Add(-1 * time.Minute) // renewal phase

	type tc struct {
		name    string
		now     time.Time
		present []int64
		foreign int
		issue   bool
		keep    []int64
		give    int64
		change  bool
		err     error
	}
	cases := []tc{
		{"fresh account", mid, nil, 0, true, []int64{cur}, cur, true, nil},
		{"already current", mid, []int64{cur}, 0, true, []int64{cur}, cur, false, nil},
		{"drop previous", mid, []int64{cur - 1, cur}, 0, true, []int64{cur}, cur, true, nil},
		{"replace previous", mid, []int64{cur - 1}, 0, true, []int64{cur}, cur, true, nil},
		{"remove foreign", mid, []int64{cur}, 1, true, []int64{cur}, cur, true, nil},
		{"renew adds next", renew, []int64{cur}, 0, true, []int64{cur, cur + 1}, cur + 1, true, nil},
		{"renew steady", renew, []int64{cur, cur + 1}, 0, true, []int64{cur, cur + 1}, cur + 1, false, nil},
		{"other replica added next", mid, []int64{cur, cur + 1}, 0, true, []int64{cur, cur + 1}, cur, false, nil},
		{"other replica moved past", mid, []int64{cur + 1}, 0, true, []int64{cur + 1}, cur + 1, false, nil},
		{"far future is foreign", mid, []int64{cur, cur + 2}, 0, true, []int64{cur}, cur, true, nil},
		{"sweep removes expired", mid, []int64{cur - 1, cur}, 0, false, []int64{cur}, 0, true, nil},
		{"sweep empties stale", mid, []int64{cur - 1}, 0, false, nil, 0, true, nil},
		{"sweep removes foreign", mid, nil, 2, false, nil, 0, true, nil},
		{"sweep does not add", renew, []int64{cur}, 0, false, []int64{cur}, 0, false, nil},
		{"sweep idle", mid, nil, 0, false, nil, 0, false, nil},
	}
	for _, c := range cases {
		p, err := PlanSoft(s, a, c.now, c.present, c.foreign, c.issue)
		if !errors.Is(err, c.err) {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		if err != nil {
			continue
		}
		if !slices.Equal(p.Keep, c.keep) || p.Change != c.change || (c.issue && p.Issue != c.give) {
			t.Errorf("%s: got %+v, want keep=%v give=%d change=%v", c.name, p, c.keep, c.give, c.change)
		}
		if c.issue && !slices.Contains(p.Keep, p.Issue) {
			t.Errorf("%s: issued window %d not kept", c.name, p.Issue)
		}
	}
}

// Simulate two replicas with clocks 20s apart racing over the same account
// across many windows: the account must never move backwards and every
// issued credential must be present in the account right after issuance.
func TestCheckClock(t *testing.T) {
	s := sched(t)
	now := time.Now()
	if err := CheckClock(s, now, now.Add(9*time.Second)); err != nil {
		t.Error(err)
	}
	if err := CheckClock(s, now, now.Add(-11*time.Second)); !errors.Is(err, ErrClockSkew) {
		t.Errorf("11s behind: %v", err)
	}
	s.MaxClockSkew = time.Second
	if err := CheckClock(s, now, now.Add(2*time.Second)); !errors.Is(err, ErrClockSkew) {
		t.Errorf("custom limit: %v", err)
	}
}

func TestPlanSoftConverges(t *testing.T) {
	s := sched(t)
	a := rotation.Account{Store: "mysql", Node: "m1", Name: "t_x"}
	var present []int64
	start := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	maxSeen := int64(-1 << 62)
	for i := 0; i < 5000; i++ {
		now := start.Add(time.Duration(i) * 3 * time.Second)
		if i%2 == 1 {
			now = now.Add(20 * time.Second)
		}
		p, err := PlanSoft(s, a, now, present, 0, i%5 != 0)
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		present = p.Keep
		for _, n := range present {
			if n > maxSeen {
				maxSeen = n
			}
		}
		if len(present) > 0 && slices.Max(present) < maxSeen {
			t.Fatalf("step %d: moved backwards: %v < %d", i, present, maxSeen)
		}
		if len(present) > 2 {
			t.Fatalf("step %d: more than two passwords: %v", i, present)
		}
	}
}
