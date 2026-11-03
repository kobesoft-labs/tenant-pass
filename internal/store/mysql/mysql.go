// Package mysql manages MySQL account passwords (MySQL 8.0.27+ / 8.4 /
// 9.x, caching_sha2_password).
//
// # Model
//
// MySQL has no per-password expiry time, but since 8.0.14 an account can
// hold two passwords at once: a primary and a secondary ("dual
// passwords"). tenant-pass uses them as two slots for consecutive windows:
//
//   - normal phase:  primary = password(cur)
//   - renewal phase: primary = password(cur+1), secondary = password(cur)
//
// so a client holding the older credential keeps working while others
// already use the newer one. A background sweeper removes passwords whose
// window has ended (soft expiry; see package store).
//
// Only caching_sha2_password hashes are sent ("IDENTIFIED WITH
// caching_sha2_password AS 0x<hash>"), never the plaintext, so passwords
// do not appear in the general log, the binary log or
// performance_schema.
//
// # Recognizing state without storing state
//
// tenant-pass reads mysql.user.authentication_string (primary) and the
// additional_password attribute (secondary), and recognizes its own
// windows by recomputing the hash for each candidate window with the
// stored salt. Nothing is trusted that tenant-pass did not compute.
//
// # Concurrency
//
// Replicas serialize per account with GET_LOCK (a server-wide named
// lock), then read, plan (store.PlanSoft) and write.
//
// # Safety checks
//
// Before changing an account, tenant-pass verifies that it exists, that
// the managed role is the only role granted to it, and that neither the
// account nor the managed role holds any global privilege (any "*_priv"
// column of mysql.user), any dynamic privilege (including SYSTEM_USER),
// any privilege on the mysql/sys/performance_schema schemas, or proxy
// rights. It also refuses when the server has mandatory_roles set, and
// never touches its own admin account. Tenant accounts are expected to
// hold privileges on their own databases or tables only.
package mysql

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"

	"github.com/kobesoft-labs/tenant-pass/internal/keyedmutex"
	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/pwhash"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
)

// Type is the store type name.
const Type = "mysql"

// safeName is a hard-coded allowlist for user and host names, applied in
// addition to the configurable account_pattern. ALTER USER cannot take
// bind parameters for the account, so these names are interpolated into
// SQL; restricting the character set makes quoting trivially correct.
var safeName = regexp.MustCompile(`^[A-Za-z0-9_.%-]{1,64}$`)

// Config configures one MySQL node.
type Config struct {
	Name     string
	Endpoint *netcfg.Resolved
	// AccountHost is the host part of managed accounts ('user'@'host').
	AccountHost string
	// ManagedRole and ManagedRoleHost name the role every managed account
	// must have been granted (GRANT tenant_pass_managed TO 'u'@'h').
	ManagedRole     string
	ManagedRoleHost string
	AccountPattern  *regexp.Regexp
	MaxConns        int
}

// Store implements store.Store for MySQL.
type Store struct {
	cfg   Config
	sched *rotation.Schedule
	db    *sql.DB
	locks keyedmutex.Map
	now   func() time.Time
}

// New creates the store. It does not verify connectivity; call Ping.
func New(cfg Config, sched *rotation.Schedule) (*Store, error) {
	for _, n := range []string{cfg.AccountHost, cfg.ManagedRole, cfg.ManagedRoleHost} {
		if !safeName.MatchString(n) {
			return nil, fmt.Errorf("mysql %s: account_host, managed_role and managed_role_host must match %s", cfg.Name, safeName)
		}
	}
	if cfg.AccountPattern == nil {
		return nil, errors.New("mysql: account_pattern is required")
	}
	dc := DriverConfig(cfg.Endpoint)
	conn, err := mysqldrv.NewConnector(dc)
	if err != nil {
		return nil, fmt.Errorf("mysql %s: %w", cfg.Name, err)
	}
	db := sql.OpenDB(conn)
	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = 4
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return &Store{cfg: cfg, sched: sched, db: db, now: time.Now}, nil
}

// DriverConfig builds a go-sql-driver/mysql configuration without going
// through a DSN string. It is also used by the SQL directory.
func DriverConfig(e *netcfg.Resolved) *mysqldrv.Config {
	dc := mysqldrv.NewConfig()
	dc.Net = "tcp"
	dc.Addr = e.Host + ":" + e.Port
	dc.User = e.User
	dc.Passwd = e.Password.Reveal()
	dc.DBName = e.Database
	dc.TLS = e.TLS // nil only when plaintext was explicitly allowed
	// Refuse to send the password in cleartext even if the server asks
	// for the mysql_clear_password plugin, and refuse legacy hashing.
	dc.AllowCleartextPasswords = false
	dc.AllowNativePasswords = false
	dc.AllowOldPasswords = false
	dc.Timeout = 5 * time.Second
	dc.ReadTimeout = 5 * time.Second
	dc.WriteTimeout = 5 * time.Second
	dc.ParseTime = true
	dc.MultiStatements = false // never; each statement is sent alone
	dc.InterpolateParams = false
	return dc
}

// Type implements store.Store.
func (s *Store) Type() string { return Type }

// Close implements store.Store.
func (s *Store) Close() { s.db.Close() }

// Ping implements store.Store.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) account(user string) rotation.Account {
	return rotation.Account{Store: Type, Node: s.cfg.Name, Name: user}
}

// quoteAccount returns 'user'@'host'. Both parts have been checked
// against safeName, which excludes quotes and backslashes.
func (s *Store) quoteAccount(user string) string {
	return "'" + user + "'@'" + s.cfg.AccountHost + "'"
}

// state is what tenant-pass knows about one account.
type state struct {
	primary, secondary int64 // window numbers; -1 means foreign, noSlot means empty
	present            []int64
	foreign            int
}

const noSlot = int64(-1 << 62)

// Issue implements store.Store.
func (s *Store) Issue(ctx context.Context, user string, repair bool) (store.Credential, error) {
	if !s.cfg.AccountPattern.MatchString(user) || !safeName.MatchString(user) {
		return store.Credential{}, store.Refused("user name does not match account_pattern")
	}
	var cred store.Credential
	err := s.withAccount(ctx, user, func(conn *sql.Conn, st state) error {
		acc := s.account(user)
		plan, err := store.PlanSoft(s.sched, acc, s.now(), st.present, st.foreign, true)
		if err != nil {
			return err
		}
		// repair is ignored: the account's state was just verified by
		// recomputing its hashes, so a rewrite could only briefly drop
		// the newer password (see apply) and gain nothing.
		_ = repair
		if plan.Change {
			if err := s.apply(ctx, conn, user, st, plan.Keep, false); err != nil {
				return err
			}
		}
		cred, err = store.Build(ctx, s.sched, acc, plan.Issue, plan.Change)
		return err
	})
	return cred, err
}

// Sweep implements store.Store: it removes expired and foreign passwords
// from every managed account on this node.
func (s *Store) Sweep(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT u.User FROM mysql.user u
		   JOIN mysql.role_edges r ON r.TO_USER = u.User AND r.TO_HOST = u.Host
		  WHERE u.Host = ? AND r.FROM_USER = ? AND r.FROM_HOST = ?`,
		s.cfg.AccountHost, s.cfg.ManagedRole, s.cfg.ManagedRoleHost)
	if err != nil {
		return s.wrap(err)
	}
	var users []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return s.wrap(err)
		}
		users = append(users, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s.wrap(err)
	}

	var managed []string
	for _, u := range users {
		if s.cfg.AccountPattern.MatchString(u) && safeName.MatchString(u) {
			managed = append(managed, u)
		}
	}
	return store.ForEachShuffled(ctx, managed, func(u string) error {
		return s.withAccount(ctx, u, func(conn *sql.Conn, st state) error {
			plan, err := store.PlanSoft(s.sched, s.account(u), s.now(), st.present, st.foreign, false)
			if err != nil || !plan.Change {
				return err
			}
			return s.apply(ctx, conn, u, st, plan.Keep, false)
		})
	})
}

// withAccount takes the in-process and server-side locks for user, runs
// the safety checks, reads the account's state and calls fn.
func (s *Store) withAccount(ctx context.Context, user string, fn func(*sql.Conn, state) error) error {
	unlock, err := s.locks.Lock(ctx, user)
	if err != nil {
		return err
	}
	defer unlock()

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return s.wrap(err)
	}
	defer conn.Close()

	// Named locks are per server and per session. The name is hashed to
	// stay within MySQL's 64-character limit.
	h := sha256.Sum256([]byte(user + "@" + s.cfg.AccountHost))
	lockName := "tenant-pass:" + hex.EncodeToString(h[:16])
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK(?, 2)`, lockName).Scan(&got); err != nil {
		return s.wrap(err)
	}
	if !got.Valid || got.Int64 != 1 {
		return fmt.Errorf("mysql %s: lock timeout", s.cfg.Name)
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `SELECT RELEASE_LOCK(?)`, lockName)

	st, err := s.inspect(ctx, conn, user)
	if err != nil {
		return err
	}
	return fn(conn, st)
}

// inspect performs the safety checks and identifies the account's
// current passwords.
func (s *Store) inspect(ctx context.Context, conn *sql.Conn, user string) (state, error) {
	host := s.cfg.AccountHost
	var (
		plugin, primaryHex, secondaryHex string
		serverUnix                       float64
	)
	err := conn.QueryRowContext(ctx, `
		SELECT plugin, HEX(authentication_string),
		       HEX(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(User_attributes, '$.additional_password')), '')),
		       UNIX_TIMESTAMP(NOW(6))
		  FROM mysql.user WHERE User = ? AND Host = ?`, user, host).Scan(
		&plugin, &primaryHex, &secondaryHex, &serverUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return state{}, store.Refused("account does not exist")
	}
	if err != nil {
		return state{}, s.wrap(err)
	}
	now := s.now()
	if err := store.CheckClock(s.sched, now, time.Unix(0, int64(serverUnix*1e9))); err != nil {
		return state{}, err
	}

	var current, mandatory string
	if err := conn.QueryRowContext(ctx, `SELECT CURRENT_USER(), @@GLOBAL.mandatory_roles`).Scan(&current, &mandatory); err != nil {
		return state{}, s.wrap(err)
	}
	if current == user+"@"+host {
		return state{}, store.Refused("account is tenant-pass's own admin account")
	}
	if strings.TrimSpace(mandatory) != "" {
		// Mandatory roles are granted to every account implicitly; their
		// privileges cannot be checked per account.
		return state{}, store.Refused("server has mandatory_roles set")
	}

	// The account must have exactly one granted role: the managed role.
	var roles, managed int
	if err := conn.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(FROM_USER = ? AND FROM_HOST = ?), 0)
		  FROM mysql.role_edges WHERE TO_USER = ? AND TO_HOST = ?`,
		s.cfg.ManagedRole, s.cfg.ManagedRoleHost, user, host).Scan(&roles, &managed); err != nil {
		return state{}, s.wrap(err)
	}
	switch {
	case managed == 0:
		return state{}, store.Refused("account has not been granted the managed role")
	case roles > 1:
		return state{}, store.Refused("account has roles other than the managed role")
	}

	// Neither the account nor the managed role (whose privileges the
	// account can activate with SET ROLE) may hold privileges that reach
	// beyond one tenant.
	for _, who := range [][2]string{{user, host}, {s.cfg.ManagedRole, s.cfg.ManagedRoleHost}} {
		if reason, err := s.privileged(ctx, conn, who[0], who[1]); err != nil {
			return state{}, err
		} else if reason != "" {
			return state{}, store.Refused("%s", reason)
		}
	}
	var roleRoles int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM mysql.role_edges WHERE TO_USER = ? AND TO_HOST = ?`,
		s.cfg.ManagedRole, s.cfg.ManagedRoleHost).Scan(&roleRoles); err != nil {
		return state{}, s.wrap(err)
	}
	if roleRoles > 0 {
		return state{}, store.Refused("managed role has roles granted to it")
	}

	st := state{primary: noSlot, secondary: noSlot}
	acc := s.account(user)
	cands := store.Candidates(s.sched, acc, now)
	identify := func(hx string) (int64, error) {
		if hx == "" {
			return noSlot, nil
		}
		raw, err := hex.DecodeString(hx)
		if err != nil {
			return 0, err
		}
		if plugin != "caching_sha2_password" {
			return -1, nil
		}
		for _, n := range cands {
			pw, _, err := s.sched.Password(ctx, acc, n)
			if err != nil {
				continue // no key for that window
			}
			// Cheap pre-check: our salt for window n is deterministic, so
			// only run the (slow) hash when the stored salt matches.
			saltSrc, err := s.sched.Salt(ctx, acc, n)
			if err != nil {
				continue
			}
			salt, _ := pwhash.MySQLSalt(saltSrc)
			if len(raw) == 70 && string(raw[7:27]) == string(salt) && pwhash.MySQLMatches(string(raw), pw) {
				return n, nil
			}
		}
		return -1, nil
	}
	if st.primary, err = identify(primaryHex); err != nil {
		return state{}, err
	}
	if st.secondary, err = identify(secondaryHex); err != nil {
		return state{}, err
	}
	for _, w := range []int64{st.primary, st.secondary} {
		switch {
		case w == noSlot:
		case w == -1:
			st.foreign++
		case !slices.Contains(st.present, w):
			st.present = append(st.present, w)
		}
	}
	return st, nil
}

// privileged returns a non-empty reason if account user@host holds any
// global privilege, any dynamic privilege, any privilege on the mysql
// schema, or proxy rights.
//
// Tenant accounts should only have privileges on their own databases or
// tables. A global privilege (even SELECT on *.*) reaches every tenant;
// privileges on the mysql schema reach every account's credentials.
// Global privilege columns are discovered dynamically ("*_priv" columns of
// mysql.user), so new server versions with new columns are covered.
func (s *Store) privileged(ctx context.Context, conn *sql.Conn, user, host string) (string, error) {
	rows, err := conn.QueryContext(ctx, `SELECT * FROM mysql.user WHERE User = ? AND Host = ?`, user, host)
	if err != nil {
		return "", s.wrap(err)
	}
	cols, err := rows.Columns()
	if err != nil {
		rows.Close()
		return "", s.wrap(err)
	}
	vals := make([]sql.RawBytes, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	found := false
	reason := ""
	for rows.Next() {
		found = true
		if err := rows.Scan(ptrs...); err != nil {
			rows.Close()
			return "", s.wrap(err)
		}
		for i, c := range cols {
			if strings.HasSuffix(strings.ToLower(c), "_priv") && string(vals[i]) != "N" {
				reason = "account holds global privilege " + c
				break
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", s.wrap(err)
	}
	if !found {
		return "account or managed role does not exist", nil
	}
	if reason != "" {
		return reason, nil
	}

	var dynamic, schemaGrants, proxies int
	if err := conn.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM mysql.global_grants WHERE USER = ? AND HOST = ?),
		       (SELECT COUNT(*) FROM mysql.db           WHERE User = ? AND Host = ? AND Db IN ('mysql', 'sys', 'performance_schema'))
		     + (SELECT COUNT(*) FROM mysql.tables_priv  WHERE User = ? AND Host = ? AND Db IN ('mysql', 'sys', 'performance_schema'))
		     + (SELECT COUNT(*) FROM mysql.columns_priv WHERE User = ? AND Host = ? AND Db IN ('mysql', 'sys', 'performance_schema'))
		     + (SELECT COUNT(*) FROM mysql.procs_priv   WHERE User = ? AND Host = ? AND Db IN ('mysql', 'sys', 'performance_schema')),
		       (SELECT COUNT(*) FROM mysql.proxies_priv WHERE User = ? AND Host = ?)`,
		user, host, user, host, user, host, user, host, user, host, user, host).Scan(&dynamic, &schemaGrants, &proxies); err != nil {
		return "", s.wrap(err)
	}
	switch {
	case dynamic > 0:
		return "account holds dynamic privileges", nil
	case schemaGrants > 0:
		return "account holds privileges on a system schema", nil
	case proxies > 0:
		return "account holds proxy privileges", nil
	}
	return "", nil
}

// apply rewrites the account so that it holds exactly the passwords of
// the windows in keep (oldest first, at most two). With an empty keep the
// account is left with a random password nobody knows, which disables it
// until the next Issue.
func (s *Store) apply(ctx context.Context, conn *sql.Conn, user string, st state, keep []int64, force bool) error {
	acc := s.account(user)
	hashFor := func(n int64) (string, error) {
		pw, _, err := s.sched.Password(ctx, acc, n)
		if err != nil {
			return "", err
		}
		src, err := s.sched.Salt(ctx, acc, n)
		if err != nil {
			return "", err
		}
		salt, err := pwhash.MySQLSalt(src)
		if err != nil {
			return "", err
		}
		return pwhash.MySQL(pw, salt)
	}
	setPrimary := func(hash string, retain bool) error {
		q := "ALTER USER " + s.quoteAccount(user) + " IDENTIFIED WITH caching_sha2_password AS " + pwhash.MySQLHex(hash)
		if retain {
			q += " RETAIN CURRENT PASSWORD"
		}
		_, err := conn.ExecContext(ctx, q)
		return s.wrap(err)
	}
	discard := func() error {
		_, err := conn.ExecContext(ctx, "ALTER USER "+s.quoteAccount(user)+" DISCARD OLD PASSWORD")
		return s.wrap(err)
	}

	switch len(keep) {
	case 0:
		rnd := make([]byte, 32)
		if _, err := rand.Read(rnd); err != nil {
			return err
		}
		pw := hex.EncodeToString(rnd[:])
		salt, _ := pwhash.MySQLSalt(rnd)
		h, err := pwhash.MySQL(pw, salt)
		if err != nil {
			return err
		}
		if err := setPrimary(h, false); err != nil {
			return err
		}
		return discard()

	case 1:
		if force || st.primary != keep[0] {
			h, err := hashFor(keep[0])
			if err != nil {
				return err
			}
			if err := setPrimary(h, false); err != nil {
				return err
			}
		}
		if force || st.secondary != noSlot {
			return discard()
		}
		return nil

	case 2:
		older, newer := keep[0], keep[1]
		if !force && st.primary == newer && st.secondary == older {
			return nil
		}
		hNew, err := hashFor(newer)
		if err != nil {
			return err
		}
		if force || st.primary != older {
			// Put the older window into the primary slot first (and drop
			// whatever was in the secondary), then rotate it into the
			// secondary slot with RETAIN CURRENT PASSWORD.
			hOld, err := hashFor(older)
			if err != nil {
				return err
			}
			if err := setPrimary(hOld, false); err != nil {
				return err
			}
			if err := discard(); err != nil {
				return err
			}
		}
		return setPrimary(hNew, true)
	}
	return errors.New("mysql: more than two windows to keep")
}

// wrap reduces driver errors to the MySQL error number, because server
// messages can echo parts of the statement (including hashes).
func (s *Store) wrap(err error) error {
	if err == nil {
		return nil
	}
	var me *mysqldrv.MySQLError
	if errors.As(err, &me) {
		return fmt.Errorf("mysql %s: error %d", s.cfg.Name, me.Number)
	}
	return fmt.Errorf("mysql %s: %w", s.cfg.Name, err)
}
