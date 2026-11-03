// Package keyedmutex provides per-key mutual exclusion whose Lock can be
// abandoned when a context is cancelled.
//
// tenant-pass serializes work on the same account inside one process, so
// that a burst of requests for one tenant results in one store update
// instead of many connections queueing on the store's own lock. Across
// processes, stores provide their own locks (PostgreSQL advisory locks,
// MySQL GET_LOCK).
package keyedmutex

import (
	"context"
	"sync"
)

// Map is a set of mutexes keyed by string. The zero value is ready to use.
// Entries are removed when no goroutine holds or waits for them, so
// memory use is bounded by concurrency, not by the number of keys ever
// seen.
type Map struct {
	mu sync.Mutex
	m  map[string]*entry
}

type entry struct {
	ch   chan struct{} // capacity 1; holding the token means holding the lock
	refs int           // holders + waiters
}

// Lock acquires the mutex for key, or returns ctx.Err() if ctx ends
// first. On success the returned function releases the lock; it must be
// called exactly once.
func (k *Map) Lock(ctx context.Context, key string) (func(), error) {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*entry)
	}
	e := k.m[key]
	if e == nil {
		e = &entry{ch: make(chan struct{}, 1)}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	select {
	case e.ch <- struct{}{}:
		return func() {
			<-e.ch
			k.release(key, e)
		}, nil
	case <-ctx.Done():
		k.release(key, e)
		return nil, ctx.Err()
	}
}

func (k *Map) release(key string, e *entry) {
	k.mu.Lock()
	e.refs--
	if e.refs == 0 {
		delete(k.m, key)
	}
	k.mu.Unlock()
}

// Len returns the number of live entries (for tests).
func (k *Map) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}
