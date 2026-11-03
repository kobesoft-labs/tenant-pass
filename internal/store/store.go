// Package store defines how tenant-pass talks to the data stores whose
// account credentials it manages, and the rotation logic that is common
// to all of them.
//
// A store (one PostgreSQL cluster, one MySQL server, one set of Redis
// servers) is called a "node" in the configuration. Each tenant lives on
// one node and maps to one account (a PostgreSQL role, a MySQL user, a
// Redis ACL user). tenant-pass never creates or deletes accounts and never
// changes privileges; it only sets the password of accounts that already
// exist and that pass the store's safety checks.
//
// Two expiry models exist:
//
//   - Hard expiry (PostgreSQL): the store itself refuses a password after
//     its expiry time (VALID UNTIL). An account has exactly one password.
//   - Soft expiry (MySQL, Redis): the store has no password expiry time,
//     but an account can hold two passwords at once. tenant-pass keeps
//     the passwords of the current window (and, near the end of a window,
//     the next one) and a background sweeper removes passwords whose
//     window has ended. A password may therefore keep working for up to
//     one sweep interval after its nominal expiry.
package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
)

// Credential is what tenant-pass hands to a client.
type Credential struct {
	Username string
	Password string
	// ExpiresAt is when the password stops being accepted for new
	// connections (hard expiry), or when it becomes eligible for removal
	// (soft expiry).
	ExpiresAt time.Time
	// RefreshAt is when the client should fetch the next credential.
	RefreshAt time.Time
	// Window and KeyID are for audit logging only.
	Window int64
	KeyID  string
	// Changed reports whether the store was modified to issue this
	// credential (for audit logging and metrics).
	Changed bool
}

// Store is one configured node.
type Store interface {
	// Type returns the store type ("postgres", "mysql", "redis").
	Type() string
	// Issue returns the current credential for account, after making
	// sure the store accepts it. If repair is true, the store is
	// re-written even if it already appears to be in the right state
	// (used when a client reports an authentication failure).
	Issue(ctx context.Context, account string, repair bool) (Credential, error)
	// Sweep removes expired passwords from every managed account. It is
	// a no-op for hard-expiry stores.
	Sweep(ctx context.Context) error
	// Ping checks connectivity to the node.
	Ping(ctx context.Context) error
	// Close releases connections.
	Close()
}

// Errors returned by stores. The server maps them to responses and audit
// reasons; their text is never sent to clients.
var (
	// ErrRefused means the account does not exist or fails a safety
	// check (privileged, not marked as managed, name does not match).
	// tenant-pass will not touch it.
	ErrRefused = errors.New("store: account refused")
	// ErrClockSkew means this replica's clock differs from the store
	// server's clock by more than the configured maximum. tenant-pass
	// refuses to write rather than risk moving accounts to the wrong
	// window (a clock far ahead would extend passwords into the future;
	// a clock far behind would move accounts backwards).
	ErrClockSkew = errors.New("store: clock skew")
)

// CheckClock compares this replica's clock (local) with a store server's
// clock (remote), read in the same round trip. It returns ErrClockSkew if
// they differ by more than the schedule's MaxClockSkew.
//
// Using the store's clock as the reference means a single replica with a
// broken clock (failed NTP, a restored VM snapshot) cannot push accounts
// into far-future windows: it refuses instead.
func CheckClock(s *rotation.Schedule, local, remote time.Time) error {
	max := s.MaxClockSkew
	if max <= 0 {
		max = rotation.DefaultMaxClockSkew
	}
	d := local.Sub(remote)
	if d < 0 {
		d = -d
	}
	if d > max {
		return fmt.Errorf("%w: local clock differs from store by %s", ErrClockSkew, d.Round(time.Millisecond))
	}
	return nil
}

// RefusedError wraps ErrRefused with a reason for the audit log.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "store: account refused: " + e.Reason }
func (e *RefusedError) Unwrap() error { return ErrRefused }

// Refused returns a RefusedError.
func Refused(format string, args ...any) error {
	return &RefusedError{Reason: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// Soft-expiry plan (MySQL, Redis)
// ---------------------------------------------------------------------------

// Plan is the outcome of planning a soft-expiry account update.
type Plan struct {
	// Keep lists the windows whose passwords the account should hold
	// after the update, oldest first (at most two).
	Keep []int64
	// Issue is the window whose credential is handed out (only
	// meaningful for Issue, not Sweep).
	Issue int64
	// Change reports whether the account must be rewritten.
	Change bool
}

// PlanSoft decides what a soft-expiry account should look like.
//
// present lists the windows whose passwords the account currently holds
// (identified by recomputing candidate passwords, never by trusting
// metadata); foreign counts passwords that match none of the candidates
// (set by hand, or by a different key). Foreign passwords are always
// removed: managed accounts must only accept tenant-pass passwords.
//
// The rules, with cur = current window and tgt = target window:
//
//  1. A window >= cur+2 cannot have been set by a replica whose clock
//     agrees with the store (see CheckClock); it is treated as foreign
//     and removed, so it cannot extend a password into the future.
//  2. If the account holds cur+1 but not cur, another replica already
//     moved past cur (its clock is slightly ahead): do not resurrect cur;
//     hand out cur+1.
//  3. Otherwise keep cur, plus cur+1 if we are in the renewal phase
//     (tgt == cur+1) or another replica already added it, and hand out
//     tgt.
//
// For sweeping (issue == false) rule 3 never adds a window that is not
// already present: the sweeper only removes. An account nobody asked for
// during a whole window ends up with no valid password at all.
func PlanSoft(s *rotation.Schedule, a rotation.Account, now time.Time, present []int64, foreign int, issue bool) (Plan, error) {
	// The error result is kept for future rules; no current rule fails.
	cur := s.Index(a, now)
	tgt := s.Target(a, now)
	has := func(n int64) bool { return slices.Contains(present, n) }

	known := present[:0:0]
	for _, n := range present {
		if n >= cur+2 {
			foreign++
			continue
		}
		known = append(known, n)
	}
	present = known

	var keep []int64
	var give int64
	switch {
	case has(cur+1) && !has(cur):
		keep, give = []int64{cur + 1}, cur+1
	case issue:
		keep = []int64{cur}
		if tgt == cur+1 || has(cur+1) {
			keep = append(keep, cur+1)
		}
		give = tgt
	default: // sweep: intersect present with {cur, cur+1}
		for _, n := range []int64{cur, cur + 1} {
			if has(n) {
				keep = append(keep, n)
			}
		}
	}

	change := foreign > 0 || !sameSet(keep, present)
	return Plan{Keep: keep, Issue: give, Change: change}, nil
}

func sameSet(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// Candidates returns the windows whose passwords a soft-expiry store
// should try to recognize at time now: from one window back (still valid
// until the sweeper runs) to two windows ahead (to detect clock skew).
func Candidates(s *rotation.Schedule, a rotation.Account, now time.Time) []int64 {
	cur := s.Index(a, now)
	return []int64{cur - 1, cur, cur + 1, cur + 2}
}

// Build returns the credential for window n.
func Build(ctx context.Context, s *rotation.Schedule, a rotation.Account, n int64, changed bool) (Credential, error) {
	pw, kid, err := s.Password(ctx, a, n)
	if err != nil {
		return Credential{}, err
	}
	return Credential{
		Username:  a.Name,
		Password:  pw,
		ExpiresAt: s.End(a, n),
		RefreshAt: s.RefreshAt(a, n),
		Window:    n,
		KeyID:     kid,
		Changed:   changed,
	}, nil
}

// SweepWorkers is how many accounts a sweep processes concurrently.
const SweepWorkers = 4

// ForEachShuffled calls fn for every name, with up to SweepWorkers calls
// in flight, in random order. Random order matters when a sweep cannot
// finish within its time budget (many accounts, slow server): a fixed
// order would starve the same accounts every time. Errors wrapping
// ErrRefused are ignored (the account is simply not managed); the first
// other error is returned after all names were attempted or ctx ended.
func ForEachShuffled(ctx context.Context, names []string, fn func(string) error) error {
	names = slices.Clone(names)
	rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })

	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, SweepWorkers)
	for _, n := range names {
		select {
		case <-ctx.Done():
			wg.Wait()
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			return firstErr
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(n string) {
			defer func() { <-sem; wg.Done() }()
			if err := fn(n); err != nil && !errors.Is(err, ErrRefused) {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(n)
	}
	wg.Wait()
	return firstErr
}
