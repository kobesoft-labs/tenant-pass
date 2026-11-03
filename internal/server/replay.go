package server

import (
	"container/list"
	"sync"
	"time"
)

// Replay cache limits. Entries live only until the pass expires
// (seconds), so these are far above normal traffic.
const (
	maxSeenPasses       = 100000 // all applications
	maxSeenPassesPerApp = 20000  // one application cannot crowd out the others
)

// passReplay remembers pass IDs until the passes expire, so that a pass
// can be exchanged for a job ticket only once. A ticket outlives the
// pass by minutes or hours, so letting one pass mint any number of
// tickets would multiply long-lived bearer tokens for no benefit.
//
// Entries are keyed by application and pass ID and expire through a
// FIFO queue (pass lifetimes are short and bounded, so insertion order
// approximates expiry order; entries that expire out of order are
// removed when they reach the front). The cache is per replica: with N
// replicas a pass can be exchanged at most N times. When an application
// reaches its quota, or the whole cache is full, new passes are refused
// (fail closed).
type passReplay struct {
	mu     sync.Mutex
	seen   map[string]*list.Element
	queue  *list.List // of *replayEntry, oldest first
	perApp map[string]int
}

type replayEntry struct {
	key, app string
	exp      time.Time
}

func (p *passReplay) prune(now time.Time) {
	for el := p.queue.Front(); el != nil; el = p.queue.Front() {
		e := el.Value.(*replayEntry)
		if now.Before(e.exp) {
			return
		}
		p.remove(el)
	}
}

func (p *passReplay) remove(el *list.Element) {
	e := el.Value.(*replayEntry)
	p.queue.Remove(el)
	delete(p.seen, e.key)
	p.perApp[e.app]--
	if p.perApp[e.app] <= 0 {
		delete(p.perApp, e.app)
	}
}

// reserve records (app, jti) and reports whether it was unused and within
// quota. The returned release function forgets the reservation again; call
// it if the ticket was not issued (for example on a transient error), so
// that the pass can be retried.
func (p *passReplay) reserve(app, jti string, exp, now time.Time) (release func(), ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen, p.queue, p.perApp = map[string]*list.Element{}, list.New(), map[string]int{}
	}
	p.prune(now)
	key := app + "\x00" + jti
	if el, dup := p.seen[key]; dup && now.Before(el.Value.(*replayEntry).exp) {
		return nil, false
	}
	if p.queue.Len() >= maxSeenPasses || p.perApp[app] >= maxSeenPassesPerApp {
		return nil, false
	}
	el := p.queue.PushBack(&replayEntry{key: key, app: app, exp: exp})
	p.seen[key] = el
	p.perApp[app]++
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if cur, ok := p.seen[key]; ok && cur == el {
			p.remove(el)
		}
	}, true
}
