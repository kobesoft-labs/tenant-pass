package keyedmutex

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMutualExclusion(t *testing.T) {
	var m Map
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := m.Lock(context.Background(), "k")
			if err != nil {
				t.Error(err)
				return
			}
			n := inside.Add(1)
			if n > maxInside.Load() {
				maxInside.Store(n)
			}
			time.Sleep(100 * time.Microsecond)
			inside.Add(-1)
			unlock()
		}()
	}
	wg.Wait()
	if maxInside.Load() != 1 {
		t.Fatalf("max concurrent holders = %d", maxInside.Load())
	}
	if m.Len() != 0 {
		t.Fatalf("leaked entries: %d", m.Len())
	}
}

func TestCancel(t *testing.T) {
	var m Map
	unlock, _ := m.Lock(context.Background(), "k")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := m.Lock(ctx, "k"); err == nil {
		t.Fatal("lock acquired while held")
	}
	// Other keys are independent.
	u2, err := m.Lock(context.Background(), "other")
	if err != nil {
		t.Fatal(err)
	}
	u2()
	unlock()
	if m.Len() != 0 {
		t.Fatalf("leaked entries: %d", m.Len())
	}
}
