package server

import (
	"sync"
	"time"
)

// maxSeenPasses bounds the replay cache. Entries live only until the
// pass expires (seconds), so this is far above normal traffic.
const maxSeenPasses = 100000

// passReplay remembers pass IDs (jti) until the passes expire, so that a
// pass can be exchanged for a job ticket only once. A ticket outlives the
// pass by minutes or hours, so letting one pass mint any number of
// tickets would multiply long-lived bearer tokens for no benefit.
//
// The cache is per replica: with N replicas a pass can be exchanged at
// most N times. When the cache is full, new passes are refused (fail
// closed) rather than forgetting older ones.
type passReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> pass expiry
}

// use records jti and reports whether it was unused (and the cache had
// room).
func (p *passReplay) use(jti string, exp, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string]time.Time{}
	}
	if e, ok := p.seen[jti]; ok && now.Before(e) {
		return false
	}
	if len(p.seen) >= maxSeenPasses {
		for k, e := range p.seen {
			if !now.Before(e) {
				delete(p.seen, k)
			}
		}
		if len(p.seen) >= maxSeenPasses {
			return false
		}
	}
	p.seen[jti] = exp
	return true
}
