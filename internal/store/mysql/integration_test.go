package mysql

// Integration tests against a real MySQL server. They run only when
// TENANT_PASS_TEST_MYSQL is set to host:port of a disposable server whose
// root password is "rootpw" (see scripts/integration.sh).
//
// The tests create the least-privilege admin account exactly as
// documented in docs/en/stores/mysql.md.

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"

	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
)

func endpoint(t *testing.T, user, password string) *netcfg.Resolved {
	t.Helper()
	addr := os.Getenv("TENANT_PASS_TEST_MYSQL")
	if addr == "" {
		t.Skip("TENANT_PASS_TEST_MYSQL not set")
	}
	host, port, _ := net.SplitHostPort(addr)
	pn, _ := strconv.Atoi(port)
	path := t.TempDir() + "/pw"
	if err := os.WriteFile(path, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	pw, err := secret.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The test server uses MySQL's auto-generated self-signed
	// certificate, so verification is disabled HERE ONLY. tenant-pass
	// itself never builds a TLS config like this.
	return &netcfg.Resolved{Host: host, Port: port, PortNum: uint16(pn), User: user, Password: pw,
		TLS: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // test only
}

func open(t *testing.T, e *netcfg.Resolved) *sql.DB {
	t.Helper()
	c, err := mysqldrv.NewConnector(DriverConfig(e))
	if err != nil {
		t.Fatal(err)
	}
	return sql.OpenDB(c)
}

func canLogin(t *testing.T, user, password string) bool {
	t.Helper()
	db := open(t, endpoint(t, user, password))
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return db.PingContext(ctx) == nil
}

var setupStatements = []string{
	`DROP USER IF EXISTS tenant_pass_admin, t_acme, t_beta, t_super, t_dyn, t_norole, t_global, t_otherrole, t_mysqldb, t_proxy`,
	`DROP ROLE IF EXISTS tenant_pass_managed, tp_dba`,
	`CREATE DATABASE IF NOT EXISTS acme`,
	// Documented setup (docs/en/stores/mysql.md).
	`CREATE ROLE tenant_pass_managed`,
	`CREATE USER tenant_pass_admin IDENTIFIED BY 'adminpw' REQUIRE SSL`,
	`GRANT CREATE USER ON *.* TO tenant_pass_admin`,
	`GRANT SELECT ON mysql.user TO tenant_pass_admin`,
	`GRANT SELECT ON mysql.global_grants TO tenant_pass_admin`,
	`GRANT SELECT ON mysql.role_edges TO tenant_pass_admin`,
	`GRANT SELECT ON mysql.db TO tenant_pass_admin`,
	`GRANT SELECT ON mysql.tables_priv TO tenant_pass_admin`,
	`GRANT SELECT ON mysql.columns_priv TO tenant_pass_admin`,
	`GRANT SELECT ON mysql.procs_priv TO tenant_pass_admin`,
	`GRANT SELECT ON mysql.proxies_priv TO tenant_pass_admin`,
	`CREATE USER t_acme IDENTIFIED BY 'initial-unused-password'`,
	`GRANT tenant_pass_managed TO t_acme`,
	`GRANT SELECT, INSERT, UPDATE, DELETE ON acme.* TO t_acme`,
	`CREATE USER t_beta IDENTIFIED BY 'initial-unused-password'`,
	`GRANT tenant_pass_managed TO t_beta`,
	// Accounts tenant-pass must refuse.
	`CREATE USER t_super IDENTIFIED BY 'x'`,
	`GRANT tenant_pass_managed TO t_super`,
	`GRANT CREATE USER ON *.* TO t_super`,
	`CREATE USER t_dyn IDENTIFIED BY 'x'`,
	`GRANT tenant_pass_managed TO t_dyn`,
	`GRANT SYSTEM_VARIABLES_ADMIN ON *.* TO t_dyn`,
	`CREATE USER t_norole IDENTIFIED BY 'x'`,
	`CREATE USER t_global IDENTIFIED BY 'x'`,
	`GRANT tenant_pass_managed TO t_global`,
	`GRANT SELECT ON *.* TO t_global`,
	`CREATE ROLE tp_dba`,
	`GRANT ALL ON *.* TO tp_dba`,
	`CREATE USER t_otherrole IDENTIFIED BY 'x'`,
	`GRANT tenant_pass_managed, tp_dba TO t_otherrole`,
	`CREATE USER t_mysqldb IDENTIFIED BY 'x'`,
	`GRANT tenant_pass_managed TO t_mysqldb`,
	`GRANT SELECT ON mysql.user TO t_mysqldb`,
	`CREATE USER t_proxy IDENTIFIED BY 'x'`,
	`GRANT tenant_pass_managed TO t_proxy`,
	`GRANT PROXY ON t_acme TO t_proxy`,
}

func setup(t *testing.T) (*Store, *rotation.Schedule) {
	t.Helper()
	root := open(t, endpoint(t, "root", "rootpw"))
	defer root.Close()
	for _, q := range setupStatements {
		if _, err := root.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	sched, err := rotation.NewSchedule(15*time.Minute, 5*time.Minute, []rotation.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdeY")}})
	if err != nil {
		t.Fatal(err)
	}
	sched.MaxClockSkew = 48 * time.Hour // tests move the clock to simulate rotation
	s, err := New(Config{
		Name: "my1", Endpoint: endpoint(t, "tenant_pass_admin", "adminpw"),
		AccountHost: "%", ManagedRole: "tenant_pass_managed", ManagedRoleHost: "%",
		AccountPattern: regexp.MustCompile(`^t_[a-z]+$`),
	}, sched)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, sched
}

func TestIntegrationIssueAndLogin(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()
	if canLogin(t, "t_acme", "initial-unused-password") == false {
		t.Fatal("setup: initial password should work before tenant-pass takes over")
	}
	c1, err := s.Issue(ctx, "t_acme", false)
	if err != nil {
		t.Fatal(err)
	}
	if !c1.Changed || !canLogin(t, "t_acme", c1.Password) {
		t.Fatal("issued password does not work")
	}
	if canLogin(t, "t_acme", "initial-unused-password") {
		t.Fatal("foreign (initial) password still works")
	}
	c2, err := s.Issue(ctx, "t_acme", false)
	if err != nil || c2.Changed || c2.Password != c1.Password {
		t.Fatalf("second issue: %+v %v", c2, err)
	}

	// The server stores only the hash tenant-pass computed.
	root := open(t, endpoint(t, "root", "rootpw"))
	defer root.Close()
	var auth string
	if err := root.QueryRow(`SELECT authentication_string FROM mysql.user WHERE user='t_acme'`).Scan(&auth); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(auth, "$A$005$") || strings.Contains(auth, c1.Password) {
		t.Fatal("unexpected authentication_string")
	}
}

func TestIntegrationRenewalAndSweep(t *testing.T) {
	s, sched := setup(t)
	ctx := context.Background()
	acc := rotation.Account{Store: Type, Node: "my1", Name: "t_beta"}
	base := time.Now()
	s.now = func() time.Time { return base }
	c1, err := s.Issue(ctx, "t_beta", false)
	if err != nil {
		t.Fatal(err)
	}

	// Renewal phase: the next window is issued and BOTH passwords work.
	s.now = func() time.Time { return sched.RefreshAt(acc, c1.Window) }
	c2, err := s.Issue(ctx, "t_beta", false)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Window != c1.Window+1 {
		t.Fatalf("renewal window = %d", c2.Window)
	}
	if !canLogin(t, "t_beta", c1.Password) || !canLogin(t, "t_beta", c2.Password) {
		t.Fatal("dual passwords not both accepted during renewal")
	}

	// After the old window ends, the sweeper removes the old password.
	s.now = func() time.Time { return sched.End(acc, c1.Window).Add(time.Second) }
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if canLogin(t, "t_beta", c1.Password) || !canLogin(t, "t_beta", c2.Password) {
		t.Fatal("sweep did not remove only the expired password")
	}

	// After the new window ends too, nothing is left.
	s.now = func() time.Time { return sched.End(acc, c2.Window).Add(time.Second) }
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if canLogin(t, "t_beta", c2.Password) {
		t.Fatal("account still usable after all windows expired")
	}
	// And issuing again works.
	c3, err := s.Issue(ctx, "t_beta", false)
	if err != nil || !canLogin(t, "t_beta", c3.Password) {
		t.Fatalf("issue after expiry: %v", err)
	}
}

func TestIntegrationClockSkew(t *testing.T) {
	s, sched := setup(t)
	sched.MaxClockSkew = 10 * time.Second
	s.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := s.Issue(context.Background(), "t_acme", false); !errors.Is(err, store.ErrClockSkew) {
		t.Fatalf("err = %v, want clock skew", err)
	}
}

func TestIntegrationRefusals(t *testing.T) {
	s, _ := setup(t)
	for _, u := range []string{"t_super", "t_dyn", "t_norole", "t_missing", "root", "tenant_pass_admin",
		"t_global", "t_otherrole", "t_mysqldb", "t_proxy"} {
		if _, err := s.Issue(context.Background(), u, false); !errors.Is(err, store.ErrRefused) {
			t.Errorf("%s: err = %v, want refused", u, err)
		}
	}
}
