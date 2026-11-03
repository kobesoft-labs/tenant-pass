package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/kms"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
)

func TestDecide(t *testing.T) {
	s, _ := rotation.NewSchedule(15*time.Minute, 5*time.Minute, []rotation.Key{{ID: "k1", MAC: kms.NewLocalMAC(make([]byte, 32))}})
	a := rotation.Account{Store: Type, Node: "pg1", Name: "t_acme"}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	tgt := s.Target(a, now)
	end := func(n int64) *time.Time { t := s.End(a, n); return &t }
	odd := s.End(a, tgt).Add(time.Second)

	cases := []struct {
		name   string
		vu     *time.Time
		repair bool
		want   action
		err    error
	}{
		{"null", nil, false, action{tgt, true}, nil},
		{"same window", end(tgt), false, action{tgt, false}, nil},
		{"same window repair", end(tgt), true, action{tgt, true}, nil},
		{"ahead by one", end(tgt + 1), false, action{tgt + 1, false}, nil},
		{"ahead by two is unmanaged", end(tgt + 2), false, action{tgt, true}, nil},
		{"old window", end(tgt - 1), false, action{tgt, true}, nil},
		{"misaligned", &odd, false, action{tgt, true}, nil},
	}
	for _, c := range cases {
		got, err := decide(s, a, now, c.vu, c.repair)
		if !errors.Is(err, c.err) || (err == nil && got != c.want) {
			t.Errorf("%s: got %+v %v, want %+v %v", c.name, got, err, c.want, c.err)
		}
	}
}
