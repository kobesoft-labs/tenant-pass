// Package ratelimit limits how many distinct tenants each application can
// request credentials for per minute.
//
// This is the main brake on a compromised application. An attacker who
// controls an application can still obtain passes only for requests the
// gateway forwards to it; if they can make the gateway forward requests
// for many tenants (see docs/en/threat-model.md), this limit bounds how
// fast they can collect credentials. Repeated requests for the same
// tenant are free, so normal traffic (many requests per tenant) is not
// affected.
//
// The limiter is per replica. With N replicas behind a load balancer the
// effective limit is up to N times the configured value; size it
// accordingly.
package ratelimit

import (
	"sync"
	"time"
)

// Window is the sliding window length.
const Window = time.Minute

// Distinct limits distinct keys per application within Window.
type Distinct struct {
	limit int
	now   func() time.Time
	mu    sync.Mutex
	apps  map[string]map[string]time.Time // app -> key -> last seen
}

// NewDistinct returns a limiter allowing limit distinct keys per app per
// Window. limit must be positive.
func NewDistinct(limit int) *Distinct {
	return &Distinct{limit: limit, now: time.Now, apps: map[string]map[string]time.Time{}}
}

// Allow records a request by app for key and reports whether it is
// within the limit. A key already seen within Window is always allowed
// (and refreshed). Memory per app is bounded by limit.
func (d *Distinct) Allow(app, key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	keys := d.apps[app]
	if keys == nil {
		keys = map[string]time.Time{}
		d.apps[app] = keys
	}
	if seen, ok := keys[key]; ok && now.Sub(seen) < Window {
		keys[key] = now
		return true
	}
	// Drop expired entries before counting.
	for k, seen := range keys {
		if now.Sub(seen) >= Window {
			delete(keys, k)
		}
	}
	if len(keys) >= d.limit {
		return false
	}
	keys[key] = now
	return true
}
