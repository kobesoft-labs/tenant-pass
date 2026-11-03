package directory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	mystore "github.com/kobesoft-labs/tenant-pass/internal/store/mysql"
	pgstore "github.com/kobesoft-labs/tenant-pass/internal/store/postgres"
)

// SQLConfig configures the SQL directory.
type SQLConfig struct {
	// Driver is "postgres" or "mysql".
	Driver   string
	Endpoint *netcfg.Resolved
	// ByHost and ByTenant are queries with exactly two parameters:
	// the lookup key (host name or tenant ID) first, the application
	// name second. They must return zero or one row with exactly the
	// columns tenant_id, node, account, enabled (in that order).
	//
	// Use $1/$2 for PostgreSQL and ?/? for MySQL. Restricting tenants to
	// applications is the query's job (via the second parameter); if
	// every application may access every tenant, say so explicitly in
	// the query, for example "AND $2::text IS NOT NULL".
	ByHost   string
	ByTenant string
}

var wantColumns = []string{"tenant_id", "node", "account", "enabled"}

// SQL is a directory backed by a PostgreSQL or MySQL database.
type SQL struct {
	db               *sql.DB
	byHost, byTenant string
}

// NewSQL opens the database and validates both queries by running them
// once (read-only) with a key that cannot exist.
func NewSQL(ctx context.Context, cfg SQLConfig) (*SQL, error) {
	var db *sql.DB
	switch cfg.Driver {
	case "postgres":
		cc, err := pgstore.ConnConfig(cfg.Endpoint)
		if err != nil {
			return nil, err
		}
		db = stdlib.OpenDB(*cc)
	case "mysql":
		conn, err := mysqldrv.NewConnector(mystore.DriverConfig(cfg.Endpoint))
		if err != nil {
			return nil, err
		}
		db = sql.OpenDB(conn)
	default:
		return nil, fmt.Errorf("directory: unknown driver %q", cfg.Driver)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)
	d := &SQL{db: db, byHost: cfg.ByHost, byTenant: cfg.ByTenant}

	for name, q := range map[string]string{"by_host": cfg.ByHost, "by_tenant": cfg.ByTenant} {
		if q == "" {
			db.Close()
			return nil, fmt.Errorf("directory: query %s is required", name)
		}
		if _, err := d.lookup(ctx, q, "tenant-pass.invalid", "tenant-pass-check"); err != nil && !errors.Is(err, ErrNotFound) {
			db.Close()
			return nil, fmt.Errorf("directory: query %s: %w", name, err)
		}
	}
	return d, nil
}

// lookup runs q in a read-only transaction. A read-only transaction means
// that even a query with side effects (a function call, a writable CTE)
// configured by mistake cannot modify the directory database.
func (d *SQL) lookup(ctx context.Context, q, key, app string) (Tenant, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Tenant{}, sanitize(err)
	}
	defer tx.Rollback() //nolint:errcheck // read-only; nothing to commit

	rows, err := tx.QueryContext(ctx, q, key, app)
	if err != nil {
		return Tenant{}, sanitize(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return Tenant{}, sanitize(err)
	}
	if !slices.Equal(cols, wantColumns) {
		return Tenant{}, fmt.Errorf("directory: query must return columns %v, got %v", wantColumns, cols)
	}
	var t Tenant
	n := 0
	for rows.Next() {
		n++
		if n > 1 {
			return Tenant{}, ErrAmbiguous
		}
		if err := rows.Scan(&t.ID, &t.Node, &t.Account, &t.Enabled); err != nil {
			return Tenant{}, sanitize(err)
		}
	}
	if err := rows.Err(); err != nil {
		return Tenant{}, sanitize(err)
	}
	if n == 0 {
		return Tenant{}, ErrNotFound
	}
	if err := t.validate(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// ByHost implements Directory.
func (d *SQL) ByHost(ctx context.Context, host, app string) (Tenant, error) {
	return d.lookup(ctx, d.byHost, host, app)
}

// ByTenant implements Directory.
func (d *SQL) ByTenant(ctx context.Context, id, app string) (Tenant, error) {
	return d.lookup(ctx, d.byTenant, id, app)
}

// Ping implements Directory.
func (d *SQL) Ping(ctx context.Context) error { return sanitize(d.db.PingContext(ctx)) }

// Close implements Directory.
func (d *SQL) Close() { d.db.Close() }

// sanitize keeps only the error class. Driver errors can quote query
// parameters (host names, tenant IDs), which are not secret, but there is
// no reason to copy server-provided text into logs verbatim.
func sanitize(err error) error {
	if err == nil {
		return nil
	}
	var me *mysqldrv.MySQLError
	if errors.As(err, &me) {
		return fmt.Errorf("directory: mysql error %d", me.Number)
	}
	type sqlStater interface{ SQLState() string }
	var ss sqlStater
	if errors.As(err, &ss) {
		return fmt.Errorf("directory: sqlstate %s", ss.SQLState())
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("directory: %w", err)
}
