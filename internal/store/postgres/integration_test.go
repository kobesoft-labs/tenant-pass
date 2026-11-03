package postgres

// Integration tests against a real PostgreSQL server. They run only when
// TENANT_PASS_TEST_PG is set to host:port of a disposable server whose
// superuser is postgres/postgres (see scripts/integration.sh).
//
// The tests set up the least-privilege admin role exactly as documented
// in docs/en/stores/postgres.md, so the documentation is tested too.

import (
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kobesoft-labs/tenant-pass/internal/kms"
	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
)

func endpoint(t *testing.T, user, password string) *netcfg.Resolved {
	t.Helper()
	addr := os.Getenv("TENANT_PASS_TEST_PG")
	if addr == "" {
		t.Skip("TENANT_PASS_TEST_PG not set")
	}
	host, port, _ := net.SplitHostPort(addr)
	pn, _ := strconv.Atoi(port)
	p := filepathSecret(t, password)
	return &netcfg.Resolved{Host: host, Port: port, PortNum: uint16(pn), User: user, Password: p, Database: "postgres"}
}

func adminEndpoint(t *testing.T) *netcfg.Resolved {
	e := endpoint(t, "tenant_pass_admin", "adminpw")
	e.Database = "tenant_pass"
	return e
}

func filepathSecret(t *testing.T, s string) secret.Value {
	t.Helper()
	path := t.TempDir() + "/pw"
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := secret.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func connect(t *testing.T, e *netcfg.Resolved) (*pgx.Conn, error) {
	cc, err := ConnConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return pgx.ConnectConfig(ctx, cc)
}

const setupSQL = `
DROP ROLE IF EXISTS t_acme, t_beta, t_super, t_nomember, t_createdb, t_nologin, t_inherit, t_predef, t_loginmember, t_adminopt;
DO $$ BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'tenant_pass_admin') THEN
    EXECUTE 'REVOKE ALL ON DATABASE tenant_pass FROM tenant_pass_admin';
  END IF;
END $$;
DROP ROLE IF EXISTS t_adminparent;
DROP ROLE IF EXISTS tenant_pass_managed, tenant_pass_admin, tp_dba_group, tp_some_user, tp_admin_parent;

-- Documented setup (docs/en/stores/postgres.md).
CREATE ROLE tenant_pass_admin LOGIN CREATEROLE PASSWORD 'adminpw';
GRANT CONNECT ON DATABASE tenant_pass TO tenant_pass_admin;
CREATE ROLE tenant_pass_managed NOLOGIN;

CREATE ROLE t_acme LOGIN IN ROLE tenant_pass_managed;
CREATE ROLE t_beta LOGIN IN ROLE tenant_pass_managed;
GRANT t_acme, t_beta TO tenant_pass_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;

-- Roles tenant-pass must refuse to touch.
CREATE ROLE t_super LOGIN SUPERUSER IN ROLE tenant_pass_managed;
CREATE ROLE t_nomember LOGIN;
CREATE ROLE t_createdb LOGIN CREATEDB IN ROLE tenant_pass_managed;
CREATE ROLE t_nologin NOLOGIN IN ROLE tenant_pass_managed;
GRANT t_nomember, t_createdb, t_nologin TO tenant_pass_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;

-- Privileges inherited through membership.
CREATE ROLE tp_dba_group NOLOGIN CREATEDB;
CREATE ROLE t_inherit LOGIN IN ROLE tenant_pass_managed, tp_dba_group;
CREATE ROLE t_predef LOGIN IN ROLE tenant_pass_managed, pg_read_all_data;
CREATE ROLE tp_some_user LOGIN;
CREATE ROLE t_loginmember LOGIN IN ROLE tenant_pass_managed, tp_some_user;
CREATE ROLE t_adminopt LOGIN IN ROLE tenant_pass_managed;
GRANT t_acme TO t_adminopt WITH ADMIN OPTION;
-- ADMIN OPTION held through a parent role.
CREATE ROLE tp_admin_parent NOLOGIN;
GRANT t_acme TO tp_admin_parent WITH ADMIN OPTION;
CREATE ROLE t_adminparent LOGIN IN ROLE tenant_pass_managed, tp_admin_parent;
GRANT t_adminparent TO tenant_pass_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
GRANT t_inherit, t_predef, t_loginmember, t_adminopt TO tenant_pass_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
`

func setup(t *testing.T) (*Store, *rotation.Schedule) {
	t.Helper()
	su, err := connect(t, endpoint(t, "postgres", "postgres"))
	if err != nil {
		t.Fatal(err)
	}
	defer su.Close(context.Background())
	// tenant-pass's own database: nobody but the admin may connect.
	var exists bool
	_ = su.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'tenant_pass')`).Scan(&exists)
	if !exists {
		if _, err := su.Exec(context.Background(), `CREATE DATABASE tenant_pass`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := su.Exec(context.Background(), `REVOKE ALL ON DATABASE tenant_pass FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(context.Background(), setupSQL); err != nil {
		t.Fatal(err)
	}
	sched, err := rotation.NewSchedule(15*time.Minute, 5*time.Minute, []rotation.Key{{ID: "k1", MAC: kms.NewLocalMAC([]byte("0123456789abcdef0123456789abcdeX"))}})
	if err != nil {
		t.Fatal(err)
	}
	// Tests move the replica's clock to simulate rotation; allow that.
	// TestIntegrationClockSkew checks the real limit.
	sched.MaxClockSkew = 48 * time.Hour
	s, err := New(context.Background(), Config{
		Name: "pg1", Endpoint: adminEndpoint(t),
		ManagedGroup: "tenant_pass_managed", AccountPattern: regexp.MustCompile(`^t_[a-z]+$`),
	}, sched)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, sched
}

func canLogin(t *testing.T, role, password string) bool {
	t.Helper()
	c, err := connect(t, endpoint(t, role, password))
	if err != nil {
		return false
	}
	c.Close(context.Background())
	return true
}

func TestIntegrationIssueAndLogin(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()

	c1, err := s.Issue(ctx, "t_acme", false)
	if err != nil {
		t.Fatal(err)
	}
	if !c1.Changed || !canLogin(t, "t_acme", c1.Password) {
		t.Fatalf("first issue: changed=%v, login failed", c1.Changed)
	}
	if canLogin(t, "t_acme", c1.Password+"x") {
		t.Fatal("wrong password accepted")
	}

	// Same window: same password, no write.
	c2, err := s.Issue(ctx, "t_acme", false)
	if err != nil || c2.Password != c1.Password || c2.Changed {
		t.Fatalf("second issue: %+v %v", c2, err)
	}

	// Repair rewrites the identical value.
	c3, err := s.Issue(ctx, "t_acme", true)
	if err != nil || c3.Password != c1.Password || !c3.Changed || !canLogin(t, "t_acme", c3.Password) {
		t.Fatalf("repair: %+v %v", c3, err)
	}

	// The plaintext password must never reach the server: the stored
	// value is a SCRAM verifier.
	su, _ := connect(t, endpoint(t, "postgres", "postgres"))
	defer su.Close(ctx)
	var stored string
	var until time.Time
	if err := su.QueryRow(ctx, `SELECT rolpassword, rolvaliduntil FROM pg_authid WHERE rolname='t_acme'`).Scan(&stored, &until); err != nil {
		t.Fatal(err)
	}
	if stored == c1.Password || len(stored) < 14 || stored[:14] != "SCRAM-SHA-256$" {
		t.Fatalf("stored password is not a SCRAM verifier")
	}
	if !until.Equal(c1.ExpiresAt) {
		t.Fatalf("VALID UNTIL = %v, want %v", until, c1.ExpiresAt)
	}
}

func TestIntegrationRotation(t *testing.T) {
	s, sched := setup(t)
	ctx := context.Background()
	c1, err := s.Issue(ctx, "t_beta", false)
	if err != nil {
		t.Fatal(err)
	}
	// Move this replica's clock to the next window's renewal point.
	acc := rotation.Account{Store: Type, Node: "pg1", Name: "t_beta"}
	s.now = func() time.Time { return sched.RefreshAt(acc, c1.Window) }
	c2, err := s.Issue(ctx, "t_beta", false)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Window != c1.Window+1 || c2.Password == c1.Password || !c2.Changed {
		t.Fatalf("rotation: %+v", c2)
	}
	if canLogin(t, "t_beta", c1.Password) || !canLogin(t, "t_beta", c2.Password) {
		t.Fatal("old password still works or new one does not")
	}
	// A replica whose clock is behind must not move the role back.
	s.now = time.Now
	c3, err := s.Issue(ctx, "t_beta", false)
	if err != nil || c3.Window != c2.Window || c3.Changed {
		t.Fatalf("lagging replica: %+v %v", c3, err)
	}
}

func TestIntegrationClockSkew(t *testing.T) {
	s, sched := setup(t)
	sched.MaxClockSkew = 10 * time.Second
	ctx := context.Background()
	for _, off := range []time.Duration{-time.Hour, 30 * time.Second, 365 * 24 * time.Hour} {
		s.now = func() time.Time { return time.Now().Add(off) }
		if _, err := s.Issue(ctx, "t_beta", false); !errors.Is(err, store.ErrClockSkew) {
			t.Errorf("offset %v: err = %v, want clock skew", off, err)
		}
	}
	s.now = time.Now
	if _, err := s.Issue(ctx, "t_beta", false); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationRefusals(t *testing.T) {
	s, _ := setup(t)
	for _, role := range []string{"t_super", "t_nomember", "t_createdb", "t_nologin", "t_missing", "tenant_pass_admin", "postgres",
		"t_inherit", "t_predef", "t_loginmember", "t_adminopt", "t_adminparent"} {
		_, err := s.Issue(context.Background(), role, false)
		if !errors.Is(err, store.ErrRefused) {
			t.Errorf("%s: err = %v, want refused", role, err)
		}
	}
}

// A database that tenants may connect to is refused: they could hold the
// advisory locks tenant-pass uses and block other tenants' rotation.
func TestIntegrationRequiresDedicatedDatabase(t *testing.T) {
	_, sched := setup(t)
	s, err := New(context.Background(), Config{
		Name: "pg1", Endpoint: endpoint(t, "tenant_pass_admin", "adminpw"), // database "postgres"
		ManagedGroup: "tenant_pass_managed", AccountPattern: regexp.MustCompile(`^t_[a-z]+$`),
	}, sched)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Issue(context.Background(), "t_acme", false); err == nil || !strings.Contains(err.Error(), "dedicated database") {
		t.Fatalf("err = %v", err)
	}
}
