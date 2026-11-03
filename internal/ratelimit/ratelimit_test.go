package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

func TestDistinct(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := NewDistinct(3)
	d.now = func() time.Time { return now }
	for i := range 3 {
		if !d.Allow("a", fmt.Sprint(i)) {
			t.Fatalf("key %d denied", i)
		}
	}
	if d.Allow("a", "x") {
		t.Fatal("4th distinct key allowed")
	}
	if !d.Allow("a", "1") {
		t.Fatal("repeat key denied")
	}
	if !d.Allow("b", "x") {
		t.Fatal("other app affected")
	}
	now = now.Add(Window)
	if !d.Allow("a", "x") {
		t.Fatal("not reset after window")
	}
	if n := len(d.apps["a"]); n > 3 {
		t.Fatalf("memory not bounded: %d", n)
	}
}
