// Package redis manages Redis (7.0+) and Valkey (7.2+) ACL user passwords.
//
// # Model
//
// A Redis ACL user can hold any number of passwords. tenant-pass keeps the
// password of the current window and, in the renewal phase, the next one
// (soft expiry; see package store). Passwords are set by their SHA-256
// hash ("ACL SETUSER <user> resetpass #<hash> ..."), so the plaintext is
// never sent to Redis and never appears in its slow log or MONITOR output.
//
// ACLs are not replicated: every server (primary, replicas, Sentinel-
// managed instances, cluster nodes) holds its own copy. A node is
// therefore a list of servers, and tenant-pass applies the same password
// set to all of them.
//
// # Recognizing state without storing state
//
// "ACL GETUSER" returns the password hashes; tenant-pass compares them
// with the hashes of its candidate windows.
//
// # Concurrency
//
// Updates are idempotent (the same window always yields the same hash),
// the plan is forward-only, and requests for one account are serialized
// inside each replica. Two replicas racing on the same account can at
// worst briefly re-add a password from the previous window that the
// sweeper removes again on its next run; they can never install a
// password tenant-pass did not derive.
//
// # Safety checks
//
// Redis has no roles, so "managed" is an explicit marker: the user must
// carry the channel rule "&<managed_marker>" (default
// "&tenant-pass:managed"), which grants nothing by itself unless the user
// may also use pub/sub commands. Users without it are never touched, not
// even by the sweeper.
//
// Before issuing, tenant-pass asks each server, with ACL DRYRUN, whether
// the user could run any of a list of administrative commands, or access
// a random key or channel. ACL DRYRUN evaluates the user's effective
// permissions (categories, selectors, subcommands), so permissions cannot
// slip through a category that happens to contain an administrative
// command (for example +@slow contains ACL and CONFIG). A static check of
// the rule text is applied as well. Any doubt refuses.
package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"

	"github.com/kobesoft-labs/tenant-pass/internal/keyedmutex"
	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/pwhash"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
)

// Type is the store type name.
const Type = "redis"

// DefaultManagedMarker is the default channel marker.
const DefaultManagedMarker = "tenant-pass:managed"

// safeName restricts user names in addition to account_pattern. ACL rules
// are separate protocol arguments (no quoting issue), but a conservative
// character set keeps names unambiguous in logs and ACL files.
var safeName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// Config configures one Redis node (a set of servers holding the same
// ACL users).
type Config struct {
	Name           string
	Servers        []*netcfg.Resolved
	AccountPattern *regexp.Regexp
	// ManagedMarker is the channel pattern that marks a user as managed.
	ManagedMarker string
	// ACLSave runs "ACL SAVE" after each change, for servers that load
	// users from an aclfile. Without it, a restarted server comes back
	// with stale passwords until the next Issue fixes them.
	ACLSave bool
}

// Store implements store.Store for Redis.
type Store struct {
	cfg     Config
	sched   *rotation.Schedule
	clients []*goredis.Client
	locks   keyedmutex.Map
	now     func() time.Time
}

// New creates the store.
func New(cfg Config, sched *rotation.Schedule) (*Store, error) {
	if len(cfg.Servers) == 0 {
		return nil, errors.New("redis: at least one server is required")
	}
	if cfg.AccountPattern == nil {
		return nil, errors.New("redis: account_pattern is required")
	}
	if cfg.ManagedMarker == "" {
		cfg.ManagedMarker = DefaultManagedMarker
	}
	if !safeName.MatchString(cfg.ManagedMarker) {
		return nil, errors.New("redis: managed_marker must match " + safeName.String())
	}
	s := &Store{cfg: cfg, sched: sched, now: time.Now}
	for _, e := range cfg.Servers {
		s.clients = append(s.clients, goredis.NewClient(&goredis.Options{
			Addr:         e.Host + ":" + e.Port,
			Username:     e.User,
			Password:     e.Password.Reveal(),
			TLSConfig:    e.TLS, // nil only when plaintext was explicitly allowed
			Protocol:     2,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			PoolSize:     4,
			// Do not send CLIENT SETINFO / MAINT_NOTIFICATIONS: the admin
			// user should need nothing but the documented commands.
			DisableIdentity:          true,
			MaintNotificationsConfig: &maintnotifications.Config{Mode: maintnotifications.ModeDisabled},
		}))
	}
	return s, nil
}

// Type implements store.Store.
func (s *Store) Type() string { return Type }

// Close implements store.Store.
func (s *Store) Close() {
	for _, c := range s.clients {
		c.Close()
	}
}

// Ping implements store.Store. Every server must answer.
func (s *Store) Ping(ctx context.Context) error {
	for i, c := range s.clients {
		if err := c.Ping(ctx).Err(); err != nil {
			return s.wrap(i, err)
		}
	}
	return nil
}

func (s *Store) account(user string) rotation.Account {
	return rotation.Account{Store: Type, Node: s.cfg.Name, Name: user}
}

func (s *Store) nameAllowed(user string) bool {
	return user != "default" && safeName.MatchString(user) && s.cfg.AccountPattern.MatchString(user)
}

// Issue implements store.Store. repair is ignored: the user's state is
// verified on every call by recomputing hashes, so there is nothing a
// forced rewrite could fix.
func (s *Store) Issue(ctx context.Context, user string, _ bool) (store.Credential, error) {
	if !s.nameAllowed(user) {
		return store.Credential{}, store.Refused("user name not allowed")
	}
	unlock, err := s.locks.Lock(ctx, user)
	if err != nil {
		return store.Credential{}, err
	}
	defer unlock()

	acc := s.account(user)
	now := s.now()
	present, foreign, perServer, err := s.inspect(ctx, user, now, true)
	if err != nil {
		return store.Credential{}, err
	}
	plan, err := store.PlanSoft(s.sched, acc, now, present, foreign, true)
	if err != nil {
		return store.Credential{}, err
	}
	changed, err := s.apply(ctx, user, plan.Keep, perServer)
	if err != nil {
		return store.Credential{}, err
	}
	return store.Build(ctx, s.sched, acc, plan.Issue, changed)
}

// Sweep implements store.Store.
//
// The sweeper only removes passwords, so it checks the marker but not
// permissions: removing passwords cannot grant anything, and skipping the
// ACL DRYRUN probes keeps the sweep cheap with many users.
func (s *Store) Sweep(ctx context.Context) error {
	// Collect user names from every server: a user may need cleanup on
	// one server only.
	names := map[string]bool{}
	for i, c := range s.clients {
		users, err := c.ACLUsers(ctx).Result()
		if err != nil {
			return s.wrap(i, err)
		}
		for _, u := range users {
			if s.nameAllowed(u) {
				names[u] = true
			}
		}
	}
	list := make([]string, 0, len(names))
	for u := range names {
		list = append(list, u)
	}
	return store.ForEachShuffled(ctx, list, func(u string) error {
		unlock, err := s.locks.Lock(ctx, u)
		if err != nil {
			return err
		}
		defer unlock()
		now := s.now()
		present, foreign, perServer, err := s.inspect(ctx, u, now, false)
		if err != nil {
			return err
		}
		plan, err := store.PlanSoft(s.sched, s.account(u), now, present, foreign, false)
		if err != nil || !plan.Change {
			return err
		}
		_, err = s.apply(ctx, u, plan.Keep, perServer)
		return err
	})
}

// serverState is the set of password hashes one server holds for a user.
type serverState struct{ hashes []string }

// inspect reads the user from every server, checks the clock and the
// marker (and, if full, the user's permissions), and returns the union of
// recognized windows, the number of foreign passwords, and each server's
// raw hash list.
func (s *Store) inspect(ctx context.Context, user string, now time.Time, full bool) ([]int64, int, []serverState, error) {
	acc := s.account(user)
	byHash := map[string]int64{}
	for _, n := range store.Candidates(s.sched, acc, now) {
		if pw, _, err := s.sched.Password(ctx, acc, n); err == nil {
			byHash[pwhash.Redis(pw)] = n
		}
	}

	var present []int64
	foreign := 0
	per := make([]serverState, len(s.clients))
	for i, c := range s.clients {
		t, err := c.Time(ctx).Result()
		if err != nil {
			return nil, 0, nil, s.wrap(i, err)
		}
		if err := store.CheckClock(s.sched, now, t); err != nil {
			return nil, 0, nil, err
		}
		raw, err := c.Do(ctx, "ACL", "GETUSER", user).Result()
		if errors.Is(err, goredis.Nil) {
			return nil, 0, nil, store.Refused("user does not exist")
		}
		if err != nil {
			return nil, 0, nil, s.wrap(i, err)
		}
		u, err := parseUser(raw)
		if err != nil {
			return nil, 0, nil, s.wrap(i, err)
		}
		if !u.hasMarker(s.cfg.ManagedMarker) {
			return nil, 0, nil, store.Refused("user does not carry the managed marker")
		}
		if full {
			if reason := u.privileged(); reason != "" {
				return nil, 0, nil, store.Refused("user has %s", reason)
			}
			if reason, err := s.dryRun(ctx, c, user); err != nil {
				return nil, 0, nil, s.wrap(i, err)
			} else if reason != "" {
				return nil, 0, nil, store.Refused("%s", reason)
			}
		}
		per[i].hashes = u.passwords
		for _, h := range u.passwords {
			if n, ok := byHash[h]; ok {
				if !slices.Contains(present, n) {
					present = append(present, n)
				}
			} else {
				foreign++
			}
		}
	}
	return present, foreign, per, nil
}

// probes are commands a managed user must not be able to run. Arguments
// are chosen so that only the command permission is tested (no keys).
var probes = [][]string{
	{"ACL", "SETUSER", "x"}, {"ACL", "GETUSER", "x"}, {"ACL", "LIST"}, {"ACL", "LOG"},
	{"CONFIG", "SET", "x", "y"}, {"CONFIG", "GET", "x"}, {"CONFIG", "REWRITE"},
	{"MODULE", "LIST"}, {"MODULE", "LOAD", "x"},
	{"DEBUG", "SLEEP", "0"}, {"SHUTDOWN"},
	{"FLUSHALL"}, {"FLUSHDB"}, {"SWAPDB", "0", "1"}, {"KEYS", "x"},
	{"CLIENT", "KILL", "ID", "1"}, {"CLIENT", "LIST"}, {"CLIENT", "PAUSE", "1"},
	{"SCRIPT", "FLUSH"}, {"FUNCTION", "FLUSH"}, {"FUNCTION", "DELETE", "x"}, {"FUNCTION", "LOAD", "x"},
	{"REPLICAOF", "NO", "ONE"}, {"SLAVEOF", "NO", "ONE"}, {"FAILOVER"},
	{"CLUSTER", "RESET"}, {"CLUSTER", "FORGET", "x"},
	{"SAVE"}, {"BGSAVE"}, {"BGREWRITEAOF"},
	{"MONITOR"}, {"SYNC"}, {"PSYNC", "?", "-1"},
	{"SLOWLOG", "RESET"}, {"LATENCY", "RESET"}, {"MEMORY", "PURGE"},
}

// dryRun asks the server whether user could run any probe command, or
// read, write or publish to a random key or channel (i.e. whether its key
// or channel scope is unrestricted). It returns a reason if so.
func (s *Store) dryRun(ctx context.Context, c *goredis.Client, user string) (string, error) {
	rnd := make([]byte, 12)
	if _, err := rand.Read(rnd); err != nil {
		return "", err
	}
	probeName := "tenant-pass:probe:" + hex.EncodeToString(rnd)
	all := append(slices.Clone(probes),
		[]string{"GET", probeName},
		[]string{"SET", probeName, "x"},
		[]string{"PUBLISH", probeName, "x"},
		[]string{"SUBSCRIBE", probeName},
	)
	for _, cmd := range all {
		args := []any{"ACL", "DRYRUN", user}
		for _, a := range cmd {
			args = append(args, a)
		}
		res, err := c.Do(ctx, args...).Result()
		if err != nil {
			// A command this server does not know (older versions) cannot
			// be run by anyone; everything else is a real failure.
			if strings.Contains(strings.ToLower(err.Error()), "not found") ||
				strings.Contains(strings.ToLower(err.Error()), "unknown command") {
				continue
			}
			return "", err
		}
		if str, ok := res.(string); ok && str == "OK" {
			name := strings.ToLower(strings.Join(cmd[:min(2, len(cmd))], " "))
			if strings.Contains(name, "tenant-pass:probe:") {
				return "user has unrestricted key or channel access (" + strings.ToLower(cmd[0]) + ")", nil
			}
			return "user may run " + name, nil
		}
	}
	return "", nil
}

// apply makes every server hold exactly the hashes for keep. It returns
// whether any server was changed.
func (s *Store) apply(ctx context.Context, user string, keep []int64, per []serverState) (bool, error) {
	acc := s.account(user)
	want := make([]string, 0, len(keep))
	for _, n := range keep {
		pw, _, err := s.sched.Password(ctx, acc, n)
		if err != nil {
			return false, err
		}
		want = append(want, pwhash.Redis(pw))
	}
	changed := false
	for i, c := range s.clients {
		if sameSet(per[i].hashes, want) {
			continue
		}
		// resetpass clears all passwords and the nopass flag; the hashes
		// that follow are then the only accepted passwords. With an
		// empty want, the user can no longer authenticate at all.
		args := []any{"ACL", "SETUSER", user, "resetpass"}
		for _, h := range want {
			args = append(args, "#"+h)
		}
		if err := c.Do(ctx, args...).Err(); err != nil {
			return changed, s.wrap(i, err)
		}
		changed = true
		if s.cfg.ACLSave {
			if err := c.Do(ctx, "ACL", "SAVE").Err(); err != nil {
				return changed, s.wrap(i, err)
			}
		}
	}
	return changed, nil
}

func sameSet(a, b []string) bool {
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

// aclUser is the subset of ACL GETUSER output tenant-pass inspects.
type aclUser struct {
	flags     []string
	passwords []string
	commands  []string // root commands field plus each selector's
	channels  string   // root channels field
}

// dangerousRules lists explicitly granted rules that are refused by the
// static check. A nil entry means the command is refused entirely
// (including every subcommand); otherwise only the bare command and the
// listed subcommands are refused. This static check is a second layer
// behind ACL DRYRUN; it catches obvious cases even if a future server
// version changes DRYRUN's behaviour.
var dangerousRules = map[string][]string{
	"acl": nil, "config": nil, "debug": nil, "module": nil, "shutdown": nil,
	"replicaof": nil, "slaveof": nil, "failover": nil, "cluster": nil,
	"sync": nil, "psync": nil, "monitor": nil, "flushall": nil, "flushdb": nil,
	"swapdb": nil, "save": nil, "bgsave": nil, "bgrewriteaof": nil, "lastsave": nil,
	"keys": nil, "sentinel": nil, "pfdebug": nil, "slowlog": nil, "latency": nil,
	"client":   {"kill", "list", "pause", "unpause", "no-evict", "no-touch"},
	"function": {"load", "delete", "flush", "restore"},
	"script":   {"flush", "kill"},
	"memory":   {"purge", "doctor", "malloc-stats"},
}

// privileged returns a non-empty reason if the rule text grants
// administrative commands or unrestricted keys.
func (u aclUser) privileged() string {
	if slices.Contains(u.flags, "allcommands") {
		return "allcommands"
	}
	if slices.Contains(u.flags, "allkeys") {
		return "allkeys"
	}
	for _, rules := range u.commands {
		for _, r := range strings.Fields(strings.ToLower(rules)) {
			if !strings.HasPrefix(r, "+") {
				continue
			}
			name := strings.TrimPrefix(r, "+")
			switch name {
			case "@all", "@admin", "@dangerous":
				return "category " + r
			}
			base, sub, hasSub := strings.Cut(name, "|") // "+config|get" -> "config", "get"
			subs, listed := dangerousRules[base]
			if !listed {
				continue
			}
			if subs == nil || !hasSub || slices.Contains(subs, sub) {
				return "command " + r
			}
		}
	}
	return ""
}

// hasMarker reports whether the root channel rules contain exactly
// "&marker".
func (u aclUser) hasMarker(marker string) bool {
	return slices.Contains(strings.Fields(u.channels), "&"+marker)
}

// parseUser decodes ACL GETUSER output in RESP2 form (a flat array of
// alternating keys and values) or RESP3 form (a map). It fails closed: if
// any field tenant-pass relies on is missing or has an unexpected type,
// the reply is rejected.
func parseUser(raw any) (aclUser, error) {
	m, err := toMap(raw)
	if err != nil {
		return aclUser{}, err
	}
	var u aclUser
	var ok bool
	if u.flags, ok = toStrings(m["flags"]); !ok {
		return aclUser{}, errors.New("unexpected ACL GETUSER reply (flags)")
	}
	if u.passwords, ok = toStrings(m["passwords"]); !ok {
		return aclUser{}, errors.New("unexpected ACL GETUSER reply (passwords)")
	}
	c, ok := m["commands"].(string)
	if !ok {
		return aclUser{}, errors.New("unexpected ACL GETUSER reply (commands)")
	}
	u.commands = append(u.commands, c)
	if u.channels, ok = m["channels"].(string); !ok {
		return aclUser{}, errors.New("unexpected ACL GETUSER reply (channels)")
	}
	if selRaw, present := m["selectors"]; present {
		sels, ok := selRaw.([]any)
		if !ok {
			return aclUser{}, errors.New("unexpected ACL GETUSER reply (selectors)")
		}
		for _, sel := range sels {
			sm, err := toMap(sel)
			if err != nil {
				return aclUser{}, err
			}
			c, ok := sm["commands"].(string)
			if !ok {
				return aclUser{}, errors.New("unexpected ACL GETUSER reply (selector commands)")
			}
			u.commands = append(u.commands, c)
		}
	}
	return u, nil
}

func toMap(raw any) (map[string]any, error) {
	switch v := raw.(type) {
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			ks, ok := k.(string)
			if !ok {
				return nil, errors.New("unexpected ACL reply key")
			}
			out[ks] = val
		}
		return out, nil
	case []any:
		if len(v)%2 != 0 {
			return nil, errors.New("unexpected ACL reply length")
		}
		out := make(map[string]any, len(v)/2)
		for i := 0; i < len(v); i += 2 {
			ks, ok := v[i].(string)
			if !ok {
				return nil, errors.New("unexpected ACL reply key")
			}
			if _, dup := out[ks]; dup {
				return nil, errors.New("duplicate ACL reply key")
			}
			out[ks] = v[i+1]
		}
		return out, nil
	}
	return nil, errors.New("unexpected ACL reply type")
}

func toStrings(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// wrap hides server error text (it can echo arguments, such as hashes)
// behind the server index and the error prefix only.
func (s *Store) wrap(i int, err error) error {
	if err == nil {
		return nil
	}
	var re goredis.Error
	if errors.As(err, &re) {
		prefix, _, _ := strings.Cut(re.Error(), " ")
		return fmt.Errorf("redis %s[%d]: %s", s.cfg.Name, i, prefix)
	}
	return fmt.Errorf("redis %s[%d]: %w", s.cfg.Name, i, err)
}
