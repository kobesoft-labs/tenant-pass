// Package directory resolves a pass to a tenant: which node the tenant
// lives on, which account it uses there, whether it is enabled, and
// whether the calling application may access it at all.
//
// Two implementations exist:
//
//   - Static: tenants listed in the configuration file. Suitable for a
//     small, slowly changing set of tenants, and for testing.
//   - SQL: two operator-supplied queries run against a PostgreSQL or
//     MySQL database that the operator already uses as the source of
//     truth for tenants.
//
// The directory is part of the trusted computing base: whoever controls
// its answers controls which account tenant-pass hands out for a host. The
// stores' own safety checks (managed group/role, no administrative
// privileges, name pattern) limit the damage a wrong answer can do.
package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kobesoft-labs/tenant-pass/pass"
)

// Tenant is a directory entry.
type Tenant struct {
	ID      string // tenant ID
	Node    string // configured node name
	Account string // account name on that node
	Enabled bool   // false: credentials must not be issued
}

// ErrNotFound means no tenant matches, or the application is not allowed
// to access the tenant. The two cases are deliberately indistinguishable.
var ErrNotFound = errors.New("directory: not found")

// ErrAmbiguous means the lookup matched more than one tenant. tenant-pass
// fails closed rather than picking one.
var ErrAmbiguous = errors.New("directory: ambiguous result")

// Directory looks up tenants.
type Directory interface {
	// ByHost returns the tenant serving host, if app may access it.
	ByHost(ctx context.Context, host, app string) (Tenant, error)
	// ByTenant returns the tenant with the given ID, if app may access it.
	ByTenant(ctx context.Context, id, app string) (Tenant, error)
	// Ping checks the directory is reachable.
	Ping(ctx context.Context) error
	// Close releases resources.
	Close()
}

// validate checks a tenant returned by any directory implementation.
func (t Tenant) validate() error {
	if !pass.TenantIDPattern.MatchString(t.ID) {
		return fmt.Errorf("directory: invalid tenant_id in result")
	}
	if !pass.NamePattern.MatchString(t.Node) {
		return fmt.Errorf("directory: invalid node in result")
	}
	if t.Account == "" || len(t.Account) > 128 {
		return fmt.Errorf("directory: invalid account in result")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Static directory
// ---------------------------------------------------------------------------

// StaticTenant is one tenant in the static directory configuration.
type StaticTenant struct {
	ID      string   `json:"id"`
	Hosts   []string `json:"hosts"`
	Node    string   `json:"node"`
	Account string   `json:"account"`
	Enabled bool     `json:"enabled"`
	// Apps lists the applications allowed to obtain credentials for
	// this tenant. It is required: there is no "any application".
	Apps []string `json:"apps"`
}

// Static is an in-memory directory.
type Static struct {
	byHost map[string]*StaticTenant
	byID   map[string]*StaticTenant
}

// NewStatic validates the tenants and builds the directory.
func NewStatic(tenants []StaticTenant) (*Static, error) {
	d := &Static{byHost: map[string]*StaticTenant{}, byID: map[string]*StaticTenant{}}
	accounts := map[string]string{} // node/account -> tenant
	for i := range tenants {
		t := &tenants[i]
		tt := Tenant{ID: t.ID, Node: t.Node, Account: t.Account}
		if err := tt.validate(); err != nil {
			return nil, fmt.Errorf("static tenant %q: %w", t.ID, err)
		}
		if len(t.Apps) == 0 {
			return nil, fmt.Errorf("static tenant %q: apps must not be empty", t.ID)
		}
		if _, dup := d.byID[t.ID]; dup {
			return nil, fmt.Errorf("static tenant %q: duplicate id", t.ID)
		}
		// Two tenants on one account would share credentials (and data).
		acct := t.Node + "/" + t.Account
		if other, dup := accounts[acct]; dup {
			return nil, fmt.Errorf("static tenants %q and %q use the same account %s", other, t.ID, acct)
		}
		accounts[acct] = t.ID
		d.byID[t.ID] = t
		for _, h := range t.Hosts {
			if _, dup := d.byHost[h]; dup {
				return nil, fmt.Errorf("static tenant %q: host %q is used twice", t.ID, h)
			}
			d.byHost[h] = t
		}
	}
	return d, nil
}

func (d *Static) result(t *StaticTenant, app string) (Tenant, error) {
	if t == nil || !slices.Contains(t.Apps, app) {
		return Tenant{}, ErrNotFound
	}
	return Tenant{ID: t.ID, Node: t.Node, Account: t.Account, Enabled: t.Enabled}, nil
}

// ByHost implements Directory.
func (d *Static) ByHost(_ context.Context, host, app string) (Tenant, error) {
	return d.result(d.byHost[host], app)
}

// ByTenant implements Directory.
func (d *Static) ByTenant(_ context.Context, id, app string) (Tenant, error) {
	return d.result(d.byID[id], app)
}

// Ping implements Directory.
func (d *Static) Ping(context.Context) error { return nil }

// Close implements Directory.
func (d *Static) Close() {}
