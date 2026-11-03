// Package postgres manages PostgreSQL role passwords.
//
// # Model
//
// Each tenant maps to one LOGIN role. For window n, tenant-pass sets
//
//	ALTER ROLE <role> PASSWORD '<SCRAM verifier for password(n)>'
//	    VALID UNTIL '<End(n)>'
//
// PostgreSQL enforces VALID UNTIL itself (hard expiry): after End(n) the
// password no longer opens new connections, even if tenant-pass is down.
// Existing connections are not affected by password changes or expiry.
//
// Only the SCRAM verifier is sent, never the password, so the plaintext
// cannot leak through the server log (log_statement = ddl), pg_stat_statements
// or a replication stream.
//
// # Recognizing state without storing state
//
// The role's rolvaliduntil tells tenant-pass which window it last set:
// tenant-pass only ever sets VALID UNTIL to a window boundary of that role,
// so an exact boundary End(k) identifies window k. Anything else (NULL,
// "infinity", a time set by hand, or a boundary under a different window
// length) is treated as unmanaged and overwritten.
//
// # Concurrency
//
// Several replicas may handle the same role at once. They serialize on a
// transaction-scoped advisory lock (pg_advisory_xact_lock) keyed by role
// name, read rolvaliduntil under the lock, and only move it forward. See
// decide for the rules.
//
// # Safety checks
//
// Before changing anything, tenant-pass verifies, under the lock, that the
// role exists, can log in, is a member of the configured managed group,
// and has none of SUPERUSER, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS
// - neither directly nor through any role it is a member of (recursively).
// Membership in predefined pg_* roles or in login roles, and ADMIN OPTION
// on any role, are refused too.
// A misconfigured or compromised directory therefore cannot make
// tenant-pass reset the password of an administrative role.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kobesoft-labs/tenant-pass/internal/keyedmutex"
	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/pwhash"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
)

// Type is the store type name.
const Type = "postgres"

// advisoryClass is the first key of the two-key advisory lock, so that
// tenant-pass locks do not collide with an application's own advisory
// locks that use the one-key form. ASCII "tpas".
const advisoryClass int32 = 0x74706173

// Config configures one PostgreSQL node.
type Config struct {
	Name     string
	Endpoint *netcfg.Resolved
	// ManagedGroup is the role every managed tenant role must be a member
	// of (for example "tenant_pass_managed").
	ManagedGroup string
	// AccountPattern restricts which role names may be managed.
	AccountPattern *regexp.Regexp
	// MaxConns bounds the admin connection pool.
	MaxConns int32
}

// Store implements store.Store for PostgreSQL.
type Store struct {
	cfg        Config
	sched      *rotation.Schedule
	pool       *pgxpool.Pool
	locks      keyedmutex.Map
	now        func() time.Time
	isolatedAt atomic.Int64 // unix nanos of the last successful checkIsolation
}

// isolationRecheck is how long a successful isolation check is trusted.
// Privileges can change after startup (a later GRANT CONNECT would
// re-open the advisory lock attack), so the check is repeated.
const isolationRecheck = 5 * time.Minute

// MinServerVersion is the oldest supported PostgreSQL (16). Before 16, a
// role may grant membership in itself to others, so a tenant could make
// another tenant's role fail the membership checks below, and CREATEROLE
// reaches every non-superuser role.
const MinServerVersion = 160000

// checkIsolation verifies, once per process, the properties the locking
// relies on. Advisory locks are scoped to one database; if tenants can
// connect to the database tenant-pass uses, any tenant could take
// pg_advisory_lock on another tenant's key and block its rotation until
// its password expires. So the admin connection must use a database that
// neither PUBLIC nor any managed role may connect to.
func (s *Store) checkIsolation(ctx context.Context) error {
	if last := s.isolatedAt.Load(); last != 0 && time.Since(time.Unix(0, last)) < isolationRecheck {
		return nil
	}
	var version int
	var publicConnect, tenantConnect bool
	var db string
	err := s.pool.QueryRow(ctx, `
		SELECT current_setting('server_version_num')::int,
		       current_database(),
		       has_database_privilege('public', current_database(), 'CONNECT'),
		       EXISTS (SELECT 1 FROM pg_roles r
		                WHERE r.rolname <> current_user
		                  AND NOT r.rolsuper
		                  AND pg_has_role(r.oid, $1::text, 'MEMBER')
		                  AND has_database_privilege(r.oid, current_database(), 'CONNECT'))`,
		s.cfg.ManagedGroup).Scan(&version, &db, &publicConnect, &tenantConnect)
	if err != nil {
		return err
	}
	switch {
	case version < MinServerVersion:
		return fmt.Errorf("postgres %s: PostgreSQL 16 or later is required (server_version_num %d)", s.cfg.Name, version)
	case publicConnect || tenantConnect:
		return fmt.Errorf("postgres %s: database %q is connectable by PUBLIC or by managed roles; "+
			"use a dedicated database for tenant-pass (REVOKE CONNECT ON DATABASE ... FROM PUBLIC)", s.cfg.Name, db)
	}
	s.isolatedAt.Store(time.Now().UnixNano())
	return nil
}

// New connects to the node. It does not verify connectivity; call Ping.
func New(ctx context.Context, cfg Config, sched *rotation.Schedule) (*Store, error) {
	if cfg.ManagedGroup == "" || cfg.AccountPattern == nil {
		return nil, errors.New("postgres: managed_group and account_pattern are required")
	}
	pc, err := poolConfig(cfg)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("postgres %s: %w", cfg.Name, err)
	}
	return &Store{cfg: cfg, sched: sched, pool: pool, now: time.Now}, nil
}

// ConnConfig builds a pgx connection configuration without going through
// a DSN. It is also used by the SQL directory.
//
// pgx.ParseConfig("") would read PG* environment variables, a service
// file and a password file; ParseConfig with an explicit keyword string
// still consults some of them for unset keys. We therefore parse a
// minimal keyword string and then overwrite every connection-relevant
// field explicitly, including TLS and fallbacks (libpq-style fallbacks
// are how sslmode=prefer degrades to plaintext).
func ConnConfig(e *netcfg.Resolved) (*pgx.ConnConfig, error) {
	cc, err := pgx.ParseConfig("sslmode=disable")
	if err != nil {
		return nil, err
	}
	cc.Host = e.Host
	cc.Port = e.PortNum
	cc.User = e.User
	cc.Password = e.Password.Reveal()
	cc.Database = e.Database
	if cc.Database == "" {
		cc.Database = "postgres"
	}
	cc.TLSConfig = e.TLS // nil only when plaintext was explicitly allowed
	cc.Fallbacks = nil
	cc.ConnectTimeout = 5 * time.Second
	cc.RuntimeParams = map[string]string{"application_name": "tenant-pass"}
	// No server-side prepared statement cache: nothing to gain for
	// ALTER ROLE, and it keeps behaviour identical behind PgBouncer.
	cc.DefaultQueryExecMode = pgx.QueryExecModeExec
	return cc, nil
}

func poolConfig(cfg Config) (*pgxpool.Config, error) {
	pc, err := pgxpool.ParseConfig("sslmode=disable")
	if err != nil {
		return nil, err
	}
	cc, err := ConnConfig(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	pc.ConnConfig = cc
	pc.MaxConns = cfg.MaxConns
	if pc.MaxConns <= 0 {
		pc.MaxConns = 4
	}
	pc.MinConns = 0
	pc.MaxConnIdleTime = 5 * time.Minute
	pc.HealthCheckPeriod = 30 * time.Second
	return pc, nil
}

// Type implements store.Store.
func (s *Store) Type() string { return Type }

// Close implements store.Store.
func (s *Store) Close() { s.pool.Close() }

// Ping implements store.Store.
// It also runs the isolation check, so check-config -connect and /readyz
// report a database that tenants can connect to.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return err
	}
	return s.checkIsolation(ctx)
}

// Sweep implements store.Store. PostgreSQL enforces expiry itself.
func (s *Store) Sweep(context.Context) error { return nil }

// action is what decide tells Issue to do.
type action struct {
	window int64 // window whose credential is handed out
	write  bool  // whether to run ALTER ROLE
}

// decide applies the forward-only rules to the role's current
// rolvaliduntil (nil when NULL or infinite), with tgt = Target(now):
//
//   - End(tgt): already set by some replica; reuse it.
//   - End(tgt+1): a replica with a slightly fast clock already moved on;
//     hand out tgt+1 (never move back).
//   - Anything else (older window, NULL, infinity, misaligned, or a
//     window >= tgt+2): set tgt.
//
// A window >= tgt+2 cannot have been set by a replica whose clock agrees
// with the server (Issue checks that before deciding), so it is treated
// as unmanaged and overwritten: leaving it would keep a password valid
// far into the future.
//
// When repair is true the chosen window is rewritten even if it already
// looks right. Since passwords are deterministic, rewriting the same
// window sets identical values; it fixes a password changed by hand
// behind tenant-pass's back while VALID UNTIL was left alone.
func decide(s *rotation.Schedule, a rotation.Account, now time.Time, validUntil *time.Time, repair bool) (action, error) {
	tgt := s.Target(a, now)
	if validUntil != nil {
		if k, ok := s.IndexOfEnd(a, *validUntil); ok {
			switch {
			case k == tgt:
				return action{window: tgt, write: repair}, nil
			case k == tgt+1:
				return action{window: tgt + 1, write: repair}, nil
			}
		}
	}
	return action{window: tgt, write: true}, nil
}

// lockKey maps a role name to the second advisory lock key. Collisions
// between different roles only cause unnecessary waiting, never
// incorrect behaviour.
func lockKey(role string) int32 {
	h := sha256.Sum256([]byte(role))
	return int32(binary.BigEndian.Uint32(h[:4]))
}

// Issue implements store.Store.
func (s *Store) Issue(ctx context.Context, role string, repair bool) (store.Credential, error) {
	if !s.cfg.AccountPattern.MatchString(role) {
		return store.Credential{}, store.Refused("role name does not match account_pattern")
	}
	if err := s.checkIsolation(ctx); err != nil {
		return store.Credential{}, err
	}
	unlock, err := s.locks.Lock(ctx, role)
	if err != nil {
		return store.Credential{}, err
	}
	defer unlock()

	acc := rotation.Account{Store: Type, Node: s.cfg.Name, Name: role}
	var cred store.Credential
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		// Bound how long we hold locks and wait for them. set_config with
		// is_local=true lasts for this transaction only, which also works
		// through transaction-pooling proxies.
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', '2s', true),
			set_config('statement_timeout', '3s', true),
			set_config('idle_in_transaction_session_timeout', '10s', true)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int4, $2::int4)`, advisoryClass, lockKey(role)); err != nil {
			return err
		}

		// Read the role and its safety attributes under the lock.
		var (
			validUntil                                  *time.Time
			infinite                                    bool
			canLogin, super, createRole, createDB, repl bool
			bypassRLS, member, isSelf                   bool
			serverNow                                   time.Time
		)
		err := tx.QueryRow(ctx, `
			SELECT
				CASE WHEN r.rolvaliduntil = 'infinity' THEN NULL ELSE r.rolvaliduntil END,
				COALESCE(r.rolvaliduntil = 'infinity', false),
				r.rolcanlogin, r.rolsuper, r.rolcreaterole, r.rolcreatedb,
				r.rolreplication, r.rolbypassrls,
				pg_has_role(r.oid, $2::text, 'MEMBER'),
				r.rolname = current_user,
				clock_timestamp()
			FROM pg_roles r
			WHERE r.rolname = $1::text`, role, s.cfg.ManagedGroup).Scan(
			&validUntil, &infinite, &canLogin, &super, &createRole, &createDB, &repl, &bypassRLS, &member, &isSelf, &serverNow)
		if errors.Is(err, pgx.ErrNoRows) {
			return store.Refused("role does not exist")
		}
		if err != nil {
			return err
		}
		switch {
		case isSelf:
			return store.Refused("role is tenant-pass's own admin role")
		case role == s.cfg.ManagedGroup:
			return store.Refused("role is the managed group itself")
		case super || createRole || createDB || repl || bypassRLS:
			return store.Refused("role has administrative attributes")
		case !canLogin:
			return store.Refused("role cannot log in")
		case !member:
			return store.Refused("role is not a member of the managed group")
		}

		// Privileges can also come from roles this role is a member of,
		// directly or indirectly (SET ROLE, or INHERIT). Walk every
		// ancestor and refuse if any of them is a predefined role
		// (pg_read_all_data, pg_execute_server_program, ...), has an
		// administrative attribute, or can log in (being a member of a
		// login role means acting as that user). Also refuse a role
		// that holds ADMIN OPTION on any role, since it could grant that
		// role to others.
		var ancAdmin, ancPredefined, ancLogin, hasAdminOption bool
		err = tx.QueryRow(ctx, `
			WITH RECURSIVE anc(oid) AS (
				SELECT m.roleid FROM pg_auth_members m
				 WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = $1::text)
				UNION
				SELECT m.roleid FROM pg_auth_members m JOIN anc ON m.member = anc.oid
			)
			SELECT
				COALESCE(bool_or(r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls), false),
				COALESCE(bool_or(r.rolname LIKE 'pg\_%'), false),
				COALESCE(bool_or(r.rolcanlogin), false),
				EXISTS (SELECT 1 FROM pg_auth_members m
				         WHERE m.admin_option AND (
				               m.member = (SELECT oid FROM pg_roles WHERE rolname = $1::text)
				            OR m.member IN (SELECT oid FROM anc)))
			FROM anc JOIN pg_roles r ON r.oid = anc.oid`, role).Scan(&ancAdmin, &ancPredefined, &ancLogin, &hasAdminOption)
		if err != nil {
			return err
		}
		switch {
		case ancAdmin:
			return store.Refused("role inherits administrative attributes through membership")
		case ancPredefined:
			return store.Refused("role is a member of a predefined pg_* role")
		case ancLogin:
			return store.Refused("role is a member of a login role")
		case hasAdminOption:
			return store.Refused("role (or a role it is a member of) holds ADMIN OPTION on another role")
		}
		_ = infinite // infinity is handled as NULL: unmanaged, overwrite

		now := s.now()
		if err := store.CheckClock(s.sched, now, serverNow); err != nil {
			return err
		}
		act, err := decide(s.sched, acc, now, validUntil, repair)
		if err != nil {
			return err
		}
		cred, err = store.Build(ctx, s.sched, acc, act.window, act.write)
		if err != nil {
			return err
		}
		if !act.write {
			return nil
		}
		salt, err := s.sched.Salt(ctx, acc, act.window)
		if err != nil {
			return err
		}
		verifier, err := pwhash.SCRAM(cred.Password, salt[:pwhash.SCRAMSaltLength])
		if err != nil {
			return err
		}
		// ALTER ROLE cannot take bind parameters. Every interpolated value
		// is generated or validated here:
		//   - the role name is quoted with pgx.Identifier (and matched
		//     account_pattern above);
		//   - the verifier consists only of [A-Za-z0-9+/=:$-] by
		//     construction (base64 and fixed text);
		//   - the timestamp is formatted from a time.Time.
		sql := fmt.Sprintf("ALTER ROLE %s PASSWORD '%s' VALID UNTIL '%s'",
			pgx.Identifier{role}.Sanitize(), verifier, cred.ExpiresAt.UTC().Format("2006-01-02 15:04:05+00"))
		_, err = tx.Exec(ctx, sql)
		return err
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			// Only the SQLSTATE goes into the error: server messages can
			// echo parts of the statement.
			return store.Credential{}, fmt.Errorf("postgres %s: sqlstate %s", s.cfg.Name, pgErr.Code)
		}
		return store.Credential{}, err
	}
	return cred, nil
}
