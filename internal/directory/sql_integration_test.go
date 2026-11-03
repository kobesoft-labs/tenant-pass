package directory

// Integration tests for the SQL directory. They run when
// TENANT_PASS_TEST_PG and/or TENANT_PASS_TEST_MYSQL are set (see
// scripts/integration.sh).

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	mysqldrv "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	mystore "github.com/kobesoft-labs/tenant-pass/internal/store/mysql"
	pgstore "github.com/kobesoft-labs/tenant-pass/internal/store/postgres"
)

func resolved(t *testing.T, env, user, pw, db string, insecureTLS bool) *netcfg.Resolved {
	t.Helper()
	addr := os.Getenv(env)
	if addr == "" {
		t.Skip(env + " not set")
	}
	host, port, _ := net.SplitHostPort(addr)
	pn, _ := strconv.Atoi(port)
	path := t.TempDir() + "/pw"
	if err := os.WriteFile(path, []byte(pw), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := secret.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &netcfg.Resolved{Host: host, Port: port, PortNum: uint16(pn), User: user, Password: v, Database: db}
	if insecureTLS {
		// Test servers use self-signed certificates. Test code only.
		r.TLS = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return r
}

func exec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func checkDirectory(t *testing.T, d *SQL) {
	t.Helper()
	ctx := context.Background()
	got, err := d.ByHost(ctx, "acme.example.com", "billing")
	if err != nil || got != (Tenant{ID: "acme", Node: "pg1", Account: "t_acme", Enabled: true}) {
		t.Fatalf("ByHost = %+v %v", got, err)
	}
	if _, err := d.ByHost(ctx, "acme.example.com", "crm"); !errors.Is(err, ErrNotFound) {
		t.Errorf("other app: %v", err)
	}
	if _, err := d.ByHost(ctx, "unverified.example.com", "billing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unverified domain: %v", err)
	}
	if got, err := d.ByTenant(ctx, "beta", "billing"); err != nil || got.Enabled {
		t.Errorf("ByTenant(beta) = %+v %v", got, err)
	}
	if _, err := d.ByHost(ctx, "dup.example.com", "billing"); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("ambiguous: %v", err)
	}
	// SQL injection through the lookup key is impossible (bind
	// parameters), but check anyway.
	if _, err := d.ByHost(ctx, "x' OR '1'='1", "billing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("injection: %v", err)
	}
}

func TestIntegrationPostgresDirectory(t *testing.T) {
	su := resolved(t, "TENANT_PASS_TEST_PG", "postgres", "postgres", "postgres", false)
	cc, _ := pgstore.ConnConfig(su)
	db := stdlib.OpenDB(*cc)
	defer db.Close()
	exec(t, db,
		`DROP TABLE IF EXISTS tp_domains, tp_tenants`,
		`DROP ROLE IF EXISTS tp_reader`,
		`CREATE TABLE tp_tenants (id text PRIMARY KEY, node text, role text, status text, app text)`,
		`CREATE TABLE tp_domains (domain text, tenant_id text, verified bool)`,
		`INSERT INTO tp_tenants VALUES ('acme','pg1','t_acme','active','billing'),('beta','pg1','t_beta','suspended','billing'),('d1','pg1','t_d1','active','billing'),('d2','pg1','t_d2','active','billing')`,
		`INSERT INTO tp_domains VALUES ('acme.example.com','acme',true),('unverified.example.com','acme',false),('dup.example.com','d1',true),('dup.example.com','d2',true)`,
		`CREATE ROLE tp_reader LOGIN PASSWORD 'readerpw'`,
		`GRANT SELECT ON tp_tenants, tp_domains TO tp_reader`,
	)
	d, err := NewSQL(context.Background(), SQLConfig{
		Driver:   "postgres",
		Endpoint: resolved(t, "TENANT_PASS_TEST_PG", "tp_reader", "readerpw", "postgres", false),
		ByHost: `SELECT t.id AS tenant_id, t.node, t.role AS account, t.status = 'active' AS enabled
		           FROM tp_domains d JOIN tp_tenants t ON t.id = d.tenant_id
		          WHERE d.domain = $1 AND d.verified AND t.app = $2`,
		ByTenant: `SELECT id AS tenant_id, node, role AS account, status = 'active' AS enabled
		             FROM tp_tenants WHERE id = $1 AND app = $2`,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	checkDirectory(t, d)

	// A query returning the wrong columns is rejected at startup.
	_, err = NewSQL(context.Background(), SQLConfig{
		Driver:   "postgres",
		Endpoint: resolved(t, "TENANT_PASS_TEST_PG", "tp_reader", "readerpw", "postgres", false),
		ByHost:   `SELECT id, node, role, true FROM tp_tenants WHERE id = $1 AND app = $2`,
		ByTenant: `SELECT id AS tenant_id, node, role AS account, true AS enabled FROM tp_tenants WHERE id = $1 AND app = $2`,
	})
	if err == nil || !strings.Contains(err.Error(), "columns") {
		t.Errorf("wrong columns accepted: %v", err)
	}
	// A query that writes fails: lookups run in read-only transactions.
	exec(t, db, `GRANT INSERT ON tp_domains TO tp_reader`)
	_, err = NewSQL(context.Background(), SQLConfig{
		Driver:   "postgres",
		Endpoint: resolved(t, "TENANT_PASS_TEST_PG", "tp_reader", "readerpw", "postgres", false),
		ByHost: `WITH w AS (INSERT INTO tp_domains VALUES ($1, 'acme', true) RETURNING 1)
		         SELECT 'x' AS tenant_id, 'pg1' AS node, 'a' AS account, true AS enabled, $2::text FROM w`,
		ByTenant: `SELECT id AS tenant_id, node, role AS account, true AS enabled FROM tp_tenants WHERE id = $1 AND app = $2`,
	})
	if err == nil {
		t.Error("writing query accepted")
	}
}

func TestIntegrationMySQLDirectory(t *testing.T) {
	root := resolved(t, "TENANT_PASS_TEST_MYSQL", "root", "rootpw", "", true)
	c, _ := mysqldrv.NewConnector(mystore.DriverConfig(root))
	db := sql.OpenDB(c)
	defer db.Close()
	exec(t, db,
		`CREATE DATABASE IF NOT EXISTS tpdir`,
		`DROP TABLE IF EXISTS tpdir.domains, tpdir.tenants`,
		`DROP USER IF EXISTS tp_reader`,
		`CREATE TABLE tpdir.tenants (id varchar(64) PRIMARY KEY, node varchar(64), role varchar(64), status varchar(16), app varchar(64))`,
		`CREATE TABLE tpdir.domains (domain varchar(253), tenant_id varchar(64), verified bool)`,
		`INSERT INTO tpdir.tenants VALUES ('acme','pg1','t_acme','active','billing'),('beta','pg1','t_beta','suspended','billing'),('d1','pg1','t_d1','active','billing'),('d2','pg1','t_d2','active','billing')`,
		`INSERT INTO tpdir.domains VALUES ('acme.example.com','acme',true),('unverified.example.com','acme',false),('dup.example.com','d1',true),('dup.example.com','d2',true)`,
		`CREATE USER tp_reader IDENTIFIED BY 'readerpw'`,
		`GRANT SELECT ON tpdir.* TO tp_reader`,
	)
	d, err := NewSQL(context.Background(), SQLConfig{
		Driver:   "mysql",
		Endpoint: resolved(t, "TENANT_PASS_TEST_MYSQL", "tp_reader", "readerpw", "tpdir", true),
		ByHost: `SELECT t.id AS tenant_id, t.node, t.role AS account, t.status = 'active' AS enabled
		           FROM domains d JOIN tenants t ON t.id = d.tenant_id
		          WHERE d.domain = ? AND d.verified AND t.app = ?`,
		ByTenant: `SELECT id AS tenant_id, node, role AS account, status = 'active' AS enabled
		             FROM tenants WHERE id = ? AND app = ?`,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	checkDirectory(t, d)
}
