// Package rotation computes the time windows and the deterministic
// per-window passwords that tenant-pass sets on store accounts.
//
// # Why deterministic passwords
//
// tenant-pass runs as several identical, stateless replicas. When two
// replicas are asked for the same account at the same time they must hand
// out the same password, otherwise each would overwrite the other's and
// clients would see random authentication failures. Instead of
// coordinating through shared state, every replica derives the password
// from the same inputs:
//
//	password(n) = base64url( HMAC-SHA256( K, "tenant-pass/v1/password" ||
//	                         LP(store) || LP(node) || LP(account) ||
//	                         LP(key ID) || BE64(W) || BE64(n) ) )
//
// where n is the window number, W the window length in seconds (so that
// changing the window length can never make a new window reuse an old
// window's number, and thereby its password), K is the rotation key in
// force at the start of window n, LP(x) is a 4-byte big-endian length followed by x,
// and BE64 is a big-endian 64-bit integer. Length prefixes make the
// encoding injective: no two different input tuples can produce the same
// HMAC input.
//
// The output is 256 bits from a PRF, so it is as strong as a random
// password. Its security rests entirely on K staying secret: whoever
// holds K can compute every account's current and future passwords for
// as long as K is in force. See docs/en/threat-model.md.
//
// # Windows
//
// Time is divided into windows of fixed length W. To avoid every account
// rotating at the same instant (a thundering herd of ALTER statements and
// client reconnects), each account's window boundaries are shifted by an
// offset derived from a hash of (store, node, account). The offset does
// not depend on K, so rotating K does not move any boundaries.
//
// A credential handed out for window n is valid until End(n). When less
// than RenewBefore remains, tenant-pass already hands out window n+1, so
// that every credential a client receives is usable for at least
// RenewBefore.
package rotation

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/kms"
)

// Key is one rotation key.
type Key struct {
	// ID names the key. It is mixed into the derivation, so changing the
	// ID of a key changes all passwords derived from it.
	ID string
	// MAC computes HMAC-SHA256 with the key material, which is held
	// either in memory (kms.LocalMAC, at least MinSecretLength random
	// bytes) or in a key management system (kms.TransitMAC).
	MAC kms.MAC
	// NotBefore is the first instant from which windows may use this key.
	// Window n uses the key with the latest NotBefore <= Start(n).
	// Distributing a new key with a NotBefore in the future lets every
	// replica switch at the same window, without coordination.
	NotBefore time.Time
}

// MinSecretLength is the minimum rotation key size in bytes.
const MinSecretLength = 32

// Schedule holds the rotation parameters. All replicas serving the same
// stores must use an identical Schedule.
type Schedule struct {
	Window      time.Duration // window length, whole seconds, >= 1m
	RenewBefore time.Duration // 0 < RenewBefore <= Window/2
	// MaxClockSkew is the largest tolerated difference between this
	// replica's clock and a store server's clock. Stores refuse to write
	// when it is exceeded (see store.CheckClock). Zero means
	// DefaultMaxClockSkew.
	MaxClockSkew time.Duration
	keys         []Key // sorted by NotBefore ascending
	cache        deriveCache
}

// DefaultMaxClockSkew is the default for Schedule.MaxClockSkew.
const DefaultMaxClockSkew = 10 * time.Second

// NewSchedule validates and returns a schedule.
func NewSchedule(window, renewBefore time.Duration, keys []Key) (*Schedule, error) {
	if window < time.Minute || window%time.Second != 0 {
		return nil, errors.New("rotation: window must be whole seconds and at least 1m")
	}
	if window > 24*time.Hour {
		return nil, errors.New("rotation: window must be at most 24h")
	}
	if renewBefore <= 0 || renewBefore > window/2 {
		return nil, errors.New("rotation: renew_before must be > 0 and <= window/2")
	}
	if len(keys) == 0 {
		return nil, errors.New("rotation: at least one key is required")
	}
	ks := append([]Key(nil), keys...)
	sort.Slice(ks, func(i, j int) bool { return ks[i].NotBefore.Before(ks[j].NotBefore) })
	ids := map[string]bool{}
	secrets := map[string]bool{}
	for i, k := range ks {
		if k.MAC == nil {
			return nil, fmt.Errorf("rotation: key %q has no key material", k.ID)
		}
		if ids[k.ID] {
			return nil, fmt.Errorf("rotation: duplicate key ID %q", k.ID)
		}
		if secrets[k.MAC.Fingerprint()] {
			return nil, fmt.Errorf("rotation: key %q reuses another key's material", k.ID)
		}
		if i > 0 && k.NotBefore.Equal(ks[i-1].NotBefore) {
			return nil, fmt.Errorf("rotation: keys %q and %q have the same not_before", ks[i-1].ID, k.ID)
		}
		ids[k.ID], secrets[k.MAC.Fingerprint()] = true, true
	}
	return &Schedule{Window: window, RenewBefore: renewBefore, keys: ks}, nil
}

// Account identifies one account in one store.
type Account struct {
	Store string // store type, e.g. "postgres"
	Node  string // configured node name
	Name  string // account (role / user) name
}

func (a Account) bytes() []byte {
	var b []byte
	b = appendLP(b, a.Store)
	b = appendLP(b, a.Node)
	b = appendLP(b, a.Name)
	return b
}

func appendLP(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// offset returns this account's boundary shift in whole seconds,
// in [0, Window).
func (s *Schedule) offset(a Account) int64 {
	h := sha256.Sum256(append([]byte("tenant-pass/v1/offset"), a.bytes()...))
	return int64(binary.BigEndian.Uint64(h[:8]) % uint64(s.Window/time.Second))
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// Index returns the number of the window that contains t for account a.
func (s *Schedule) Index(a Account, t time.Time) int64 {
	w := int64(s.Window / time.Second)
	return floorDiv(t.Unix()-s.offset(a), w)
}

// Start returns the first instant of window n for account a.
func (s *Schedule) Start(a Account, n int64) time.Time {
	return time.Unix(n*int64(s.Window/time.Second)+s.offset(a), 0).UTC()
}

// End returns the instant at which window n ends (exclusive), which is
// also the expiry of credentials for window n.
func (s *Schedule) End(a Account, n int64) time.Time {
	return s.Start(a, n+1)
}

// IndexOfEnd returns n such that End(a, n) == t, if t is exactly a window
// boundary for a. Stores use it to recognize expiry times that
// tenant-pass itself set.
func (s *Schedule) IndexOfEnd(a Account, t time.Time) (int64, bool) {
	if t.Nanosecond() != 0 {
		return 0, false
	}
	w := int64(s.Window / time.Second)
	d := t.Unix() - s.offset(a)
	if d%w != 0 {
		return 0, false
	}
	return floorDiv(d, w) - 1, true
}

// Target returns the window whose credentials should be handed out at t:
// the current window, or the next one if at most RenewBefore remains
// (so a client that refreshes exactly at RefreshAt gets the next window).
func (s *Schedule) Target(a Account, t time.Time) int64 {
	n := s.Index(a, t)
	if s.End(a, n).Sub(t) <= s.RenewBefore {
		n++
	}
	return n
}

// RefreshAt returns the time from which a client holding a window-n
// credential should fetch a new one: RenewBefore before End(n). From that
// point on, tenant-pass hands out window n+1.
func (s *Schedule) RefreshAt(a Account, n int64) time.Time {
	return s.End(a, n).Add(-s.RenewBefore)
}

// keyFor returns the key in force for window n.
func (s *Schedule) keyFor(a Account, n int64) (Key, error) {
	start := s.Start(a, n)
	for i := len(s.keys) - 1; i >= 0; i-- {
		if !s.keys[i].NotBefore.After(start) {
			return s.keys[i], nil
		}
	}
	return Key{}, errors.New("rotation: no key is in force for this window")
}

// derive computes HMAC(K, label || account || LP(keyID) || BE64(n)).
//
// Results are cached until the window has long ended: the value is a
// pure function of its inputs, and with a remote key (Vault Transit) the
// cache keeps the KMS off the hot path (MySQL and Redis recompute several
// candidate windows per request). The cache holds derived passwords in
// memory, which tenant-pass does anyway while serving a request; it is
// bounded in size and never written anywhere.
func (s *Schedule) derive(ctx context.Context, label string, a Account, n int64) ([]byte, string, error) {
	k, err := s.keyFor(a, n)
	if err != nil {
		return nil, "", err
	}
	var msg []byte
	msg = append(msg, label...)
	msg = append(msg, a.bytes()...)
	msg = appendLP(msg, k.ID)
	msg = binary.BigEndian.AppendUint64(msg, uint64(s.Window/time.Second))
	msg = binary.BigEndian.AppendUint64(msg, uint64(n))

	ck := string(msg)
	if v, ok := s.cache.get(ck); ok {
		return v, k.ID, nil
	}
	sum, err := k.MAC.MAC(ctx, msg)
	if err != nil {
		return nil, "", fmt.Errorf("rotation: key %q: %w", k.ID, err)
	}
	if len(sum) != sha256.Size {
		return nil, "", errors.New("rotation: MAC returned wrong length")
	}
	// Keep until two windows after the window ends; long enough for the
	// sweeper, short enough to bound memory.
	s.cache.put(ck, sum, s.End(a, n).Add(2*s.Window))
	return sum, k.ID, nil
}

// Password returns the password for account a in window n (43 characters
// of base64url, 256 bits) and the ID of the key it was derived from.
func (s *Schedule) Password(ctx context.Context, a Account, n int64) (string, string, error) {
	sum, kid, err := s.derive(ctx, "tenant-pass/v1/password", a, n)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), kid, nil
}

// Salt returns 32 deterministic bytes for use as a password-hash salt in
// window n. Stores that hash passwords themselves (PostgreSQL SCRAM,
// MySQL caching_sha2_password) need every replica to produce the same
// hash, so the salt cannot be random. It is still unique per account and
// window, which is what a salt is for.
func (s *Schedule) Salt(ctx context.Context, a Account, n int64) ([]byte, error) {
	sum, _, err := s.derive(ctx, "tenant-pass/v1/salt", a, n)
	return sum, err
}

// LockName returns an unpredictable, stable name for a store-side lock on
// account a: hex(HMAC(K0, "tenant-pass/v1/lock" || A))[:32], where K0 is
// the earliest configured key. Store lock namespaces (MySQL GET_LOCK) are
// shared with tenants; a predictable name would let any tenant hold the
// lock for another tenant's account and block its rotation.
func (s *Schedule) LockName(ctx context.Context, a Account) (string, error) {
	k := s.keys[0]
	msg := append([]byte("tenant-pass/v1/lock"), a.bytes()...)
	ck := "lock:" + string(msg)
	if v, ok := s.cache.get(ck); ok {
		return string(v), nil
	}
	sum, err := k.MAC.MAC(ctx, msg)
	if err != nil {
		return "", fmt.Errorf("rotation: key %q: %w", k.ID, err)
	}
	name := fmt.Sprintf("%x", sum[:16])
	s.cache.put(ck, []byte(name), time.Now().Add(24*time.Hour))
	return name, nil
}

// deriveCache is a bounded, expiring LRU map. With many accounts a
// "clear everything when full" policy would repeatedly drop the whole
// cache and, with a remote key, turn every sweep into a burst of KMS
// calls; LRU eviction drops only the least recently used values.
type deriveCache struct {
	mu  sync.Mutex
	m   map[string]*list.Element
	lru *list.List // front = most recently used
}

type cacheEntry struct {
	k   string
	v   []byte
	exp time.Time
}

// maxCacheEntries bounds the cache (about 8 values per active account).
const maxCacheEntries = 200000

func (c *deriveCache) get(k string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[k]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if time.Now().After(e.exp) {
		c.lru.Remove(el)
		delete(c.m, k)
		return nil, false
	}
	c.lru.MoveToFront(el)
	// Return a copy: callers must not be able to corrupt cached values.
	return append([]byte(nil), e.v...), true
}

func (c *deriveCache) put(k string, v []byte, exp time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]*list.Element)
		c.lru = list.New()
	}
	if el, ok := c.m[k]; ok {
		el.Value.(*cacheEntry).v = append([]byte(nil), v...)
		el.Value.(*cacheEntry).exp = exp
		c.lru.MoveToFront(el)
		return
	}
	c.m[k] = c.lru.PushFront(&cacheEntry{k: k, v: append([]byte(nil), v...), exp: exp})
	for c.lru.Len() > maxCacheEntries {
		old := c.lru.Back()
		c.lru.Remove(old)
		delete(c.m, old.Value.(*cacheEntry).k)
	}
}

// CheckCurrentKey returns an error if no key is in force right now (for
// any account). It is used at startup to fail fast on a configuration
// where every key's not_before is in the future.
func (s *Schedule) CheckCurrentKey(now time.Time) error {
	// The earliest window start of any account that contains now is
	// at most one window in the past.
	if s.keys[0].NotBefore.After(now.Add(-s.Window)) {
		return errors.New("rotation: the earliest key's not_before must be at least one window in the past")
	}
	return nil
}
