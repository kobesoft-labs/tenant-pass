package redis

// Integration tests against real Redis servers. They run only when
// TENANT_PASS_TEST_REDIS is set to a comma-separated list of host:port of
// disposable servers whose default user has no password (see
// scripts/integration.sh). The tests then lock the default user down.
//
// The admin user is created exactly as documented in
// docs/en/stores/redis.md.

import (
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/kobesoft-labs/tenant-pass/internal/kms"
	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/rotation"
	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	"github.com/kobesoft-labs/tenant-pass/internal/store"
)

const bootstrapPW = "bootstrap-pw"

func addrs(t *testing.T) []string {
	t.Helper()
	v := os.Getenv("TENANT_PASS_TEST_REDIS")
	if v == "" {
		t.Skip("TENANT_PASS_TEST_REDIS not set")
	}
	return strings.Split(v, ",")
}

// bootstrap returns a client as the default user, which the tests protect
// with a password on first use.
func bootstrap(t *testing.T, addr string) *goredis.Client {
	t.Helper()
	ctx := context.Background()
	c := goredis.NewClient(&goredis.Options{Addr: addr, Protocol: 2, DisableIdentity: true})
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		c = goredis.NewClient(&goredis.Options{Addr: addr, Protocol: 2, DisableIdentity: true, Password: bootstrapPW})
	} else if err := c.Do(ctx, "ACL", "SETUSER", "default", "resetpass", ">"+bootstrapPW).Err(); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
		c = goredis.NewClient(&goredis.Options{Addr: addr, Protocol: 2, DisableIdentity: true, Password: bootstrapPW})
	}
	if err := c.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func resolved(t *testing.T, addr, user, password string) *netcfg.Resolved {
	host, port, _ := net.SplitHostPort(addr)
	path := t.TempDir() + "/pw"
	if err := os.WriteFile(path, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	pw, err := secret.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return &netcfg.Resolved{Host: host, Port: port, User: user, Password: pw}
}

func setup(t *testing.T) (*Store, *rotation.Schedule, []string) {
	t.Helper()
	ctx := context.Background()
	as := addrs(t)
	var servers []*netcfg.Resolved
	for _, a := range as {
		c := bootstrap(t, a)
		for _, cmd := range [][]any{
			{"ACL", "DELUSER", "tenant_pass_admin", "t_acme", "t_beta", "t_admin", "t_sel", "t_slow", "t_allkeys", "t_nomark", "t_allchan"},
			// Documented admin user (docs/en/stores/redis.md).
			{"ACL", "SETUSER", "tenant_pass_admin", "on", ">adminpw", "-@all",
				"+acl|getuser", "+acl|setuser", "+acl|users", "+acl|dryrun", "+acl|save", "+time", "+ping", "+auth", "+hello"},
			// Managed tenants (documented form).
			{"ACL", "SETUSER", "t_acme", "on", ">initial-unused", "resetchannels", "&tenant-pass:managed", "-@all", "+get", "+set", "+del", "~t:acme:*"},
			{"ACL", "SETUSER", "t_beta", "on", "resetchannels", "&tenant-pass:managed", "-@all", "+get", "~t:beta:*"},
			// Users tenant-pass must refuse.
			{"ACL", "SETUSER", "t_admin", "on", "resetchannels", "&tenant-pass:managed", "-@all", "+@admin"},
			{"ACL", "SETUSER", "t_sel", "on", "resetchannels", "&tenant-pass:managed", "-@all", "+get", "~t:sel:*", "(+@all ~*)"},
			// @slow contains ACL and CONFIG: only DRYRUN sees that.
			{"ACL", "SETUSER", "t_slow", "on", "resetchannels", "&tenant-pass:managed", "-@all", "+@slow", "~t:slow:*"},
			{"ACL", "SETUSER", "t_allkeys", "on", "resetchannels", "&tenant-pass:managed", "-@all", "+get", "~*"},
			{"ACL", "SETUSER", "t_allchan", "on", "resetchannels", "&tenant-pass:managed", "&*", "-@all", "+get", "+publish", "~t:allchan:*"},
			{"ACL", "SETUSER", "t_nomark", "on", ">keep-me", "resetchannels", "-@all", "+get", "~t:nomark:*"},
		} {
			if err := c.Do(ctx, cmd...).Err(); err != nil {
				t.Fatalf("%v: %v", cmd, err)
			}
		}
		servers = append(servers, resolved(t, a, "tenant_pass_admin", "adminpw"))
	}
	sched, err := rotation.NewSchedule(15*time.Minute, 5*time.Minute, []rotation.Key{{ID: "k1", MAC: kms.NewLocalMAC([]byte("0123456789abcdef0123456789abcdeZ"))}})
	if err != nil {
		t.Fatal(err)
	}
	sched.MaxClockSkew = 48 * time.Hour // tests move the clock to simulate rotation
	s, err := New(Config{Name: "rd1", Servers: servers, AccountPattern: regexp.MustCompile(`^t_[a-z]+$`)}, sched)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, sched, as
}

func canAuth(t *testing.T, addr, user, password string) bool {
	t.Helper()
	c := goredis.NewClient(&goredis.Options{Addr: addr, Protocol: 2, DisableIdentity: true, Username: user, Password: password, MaxRetries: -1})
	defer c.Close()
	// Tenant users may not run PING; NOPERM still proves that AUTH
	// succeeded (an authentication failure is reported as WRONGPASS).
	err := c.Ping(context.Background()).Err()
	return err == nil || strings.HasPrefix(err.Error(), "NOPERM")
}

func canAuthAll(t *testing.T, as []string, user, password string) bool {
	for _, a := range as {
		if !canAuth(t, a, user, password) {
			return false
		}
	}
	return true
}

func canAuthAny(t *testing.T, as []string, user, password string) bool {
	for _, a := range as {
		if canAuth(t, a, user, password) {
			return true
		}
	}
	return false
}

func TestIntegrationIssueRenewSweep(t *testing.T) {
	s, sched, as := setup(t)
	ctx := context.Background()
	acc := rotation.Account{Store: Type, Node: "rd1", Name: "t_acme"}
	base := time.Now()
	s.now = func() time.Time { return base }

	c1, err := s.Issue(ctx, "t_acme", false)
	if err != nil {
		t.Fatal(err)
	}
	if !canAuthAll(t, as, "t_acme", c1.Password) {
		t.Fatal("issued password not accepted on every server")
	}
	if canAuthAny(t, as, "t_acme", "initial-unused") {
		t.Fatal("foreign password still accepted")
	}
	if c2, _ := s.Issue(ctx, "t_acme", false); c2.Changed || c2.Password != c1.Password {
		t.Fatal("second issue changed the user")
	}

	s.now = func() time.Time { return sched.RefreshAt(acc, c1.Window) }
	c2, err := s.Issue(ctx, "t_acme", false)
	if err != nil || c2.Window != c1.Window+1 {
		t.Fatalf("renewal: %+v %v", c2, err)
	}
	if !canAuthAll(t, as, "t_acme", c1.Password) || !canAuthAll(t, as, "t_acme", c2.Password) {
		t.Fatal("both passwords must work during renewal")
	}

	s.now = func() time.Time { return sched.End(acc, c1.Window).Add(time.Second) }
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if canAuthAny(t, as, "t_acme", c1.Password) || !canAuthAll(t, as, "t_acme", c2.Password) {
		t.Fatal("sweep must remove exactly the expired password")
	}
	s.now = func() time.Time { return sched.End(acc, c2.Window).Add(time.Second) }
	if err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if canAuthAny(t, as, "t_acme", c2.Password) {
		t.Fatal("user still usable after all windows expired")
	}
}

// A server that lost its ACL state (for example restarted without an
// aclfile) is brought back in line with the others.
func TestIntegrationDivergedServer(t *testing.T) {
	s, _, as := setup(t)
	if len(as) < 2 {
		t.Skip("needs two servers")
	}
	ctx := context.Background()
	c1, err := s.Issue(ctx, "t_beta", false)
	if err != nil {
		t.Fatal(err)
	}
	b := bootstrap(t, as[1])
	if err := b.Do(ctx, "ACL", "SETUSER", "t_beta", "resetpass", ">stale").Err(); err != nil {
		t.Fatal(err)
	}
	c2, err := s.Issue(ctx, "t_beta", false)
	if err != nil || !c2.Changed {
		t.Fatalf("diverged server not repaired: %+v %v", c2, err)
	}
	if !canAuthAll(t, as, "t_beta", c1.Password) || canAuth(t, as[1], "t_beta", "stale") {
		t.Fatal("servers not converged")
	}
}

// The sweeper must never touch users without the managed marker, even if
// their names match account_pattern.
func TestIntegrationSweepRespectsMarker(t *testing.T) {
	s, _, as := setup(t)
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !canAuthAll(t, as, "t_nomark", "keep-me") {
		t.Fatal("sweeper removed the password of an unmarked user")
	}
}

func TestIntegrationClockSkew(t *testing.T) {
	s, sched, _ := setup(t)
	sched.MaxClockSkew = 10 * time.Second
	s.now = func() time.Time { return time.Now().Add(-time.Hour) }
	if _, err := s.Issue(context.Background(), "t_acme", false); !errors.Is(err, store.ErrClockSkew) {
		t.Fatalf("err = %v, want clock skew", err)
	}
}

func TestIntegrationRefusals(t *testing.T) {
	s, _, as := setup(t)
	ctx := context.Background()
	for _, u := range []string{"t_admin", "t_sel", "t_missing", "default", "tenant_pass_admin", "t_slow", "t_allkeys", "t_allchan", "t_nomark"} {
		if _, err := s.Issue(ctx, u, false); !errors.Is(err, store.ErrRefused) {
			t.Errorf("%s: err = %v, want refused", u, err)
		}
	}
	// tenant-pass must never create users.
	b := bootstrap(t, as[0])
	if err := b.Do(ctx, "ACL", "GETUSER", "t_missing").Err(); !errors.Is(err, goredis.Nil) {
		t.Errorf("t_missing was created: %v", err)
	}
}
