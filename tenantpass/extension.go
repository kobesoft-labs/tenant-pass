package tenantpass

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/kobesoft-labs/tenant-pass/internal/server"
)

// Options configures Serve.
type Options struct {
	// ConfigPath is the tenant-pass configuration file (required).
	ConfigPath string
	// Version is logged at startup.
	Version string
	// Extensions are mounted on the same listener as the core endpoints.
	Extensions []Extension
}

// Extension adds routes to a tenant-pass server.
//
// Mount is called once by Serve, after the configuration has been loaded
// and before the listener opens. It returns the routes to serve, keyed by
// net/http ServeMux patterns (for example "POST /v1/storage"); the
// patterns must not use the core's paths (/v1/credentials,
// /v1/job-tickets, /healthz, /readyz) or "/". Responses get the same
// security headers as the core (Cache-Control: no-store and others).
//
// An error from Mount stops Serve: an extension that cannot start is a
// configuration error, like any other.
type Extension struct {
	// Name identifies the extension in logs and errors
	// (^[a-z][a-z0-9-]{0,31}$).
	Name string
	// Mount returns the routes (required).
	Mount func(ctx context.Context, h Host) (map[string]http.Handler, error)
	// Ready, if set, is included in /readyz (cached with the core checks
	// for 5 seconds; it should return quickly).
	Ready func(ctx context.Context) error
	// Close, if set, is called once when Serve returns.
	Close func()
}

// Host is what an extension gets from the server. It deliberately
// exposes no keys, tokens or configuration of the core.
type Host struct {
	// Logger is the server's structured logger (JSON, configured level).
	Logger *slog.Logger
}

var extensionName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func (o Options) validate() error {
	if o.ConfigPath == "" {
		return errors.New("tenantpass: ConfigPath is required")
	}
	seen := map[string]bool{}
	for _, e := range o.Extensions {
		if !extensionName.MatchString(e.Name) {
			return fmt.Errorf("tenantpass: invalid extension name %q", e.Name)
		}
		if seen[e.Name] {
			return fmt.Errorf("tenantpass: duplicate extension %q", e.Name)
		}
		seen[e.Name] = true
		if e.Mount == nil {
			return fmt.Errorf("tenantpass: extension %q: Mount is required", e.Name)
		}
	}
	return nil
}

// patternPath returns the path part of a ServeMux pattern
// ("[METHOD ][HOST]/PATH").
func patternPath(p string) string {
	if i := strings.IndexByte(p, ' '); i >= 0 {
		p = strings.TrimLeft(p[i+1:], " ")
	}
	if i := strings.IndexByte(p, '/'); i > 0 {
		p = p[i:] // drop a host
	}
	return p
}

// checkPattern rejects patterns that would shadow or collide with the
// core's routes. Host patterns and escaped paths are refused outright:
// ServeMux gives a host pattern precedence over every host-less core route,
// and decodes %XX before matching, so either could take over a core path.
func checkPattern(p string) error {
	if strings.Contains(p, "%") {
		return fmt.Errorf("route pattern %q: escaped characters are not allowed", p)
	}
	rest := p
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		rest = strings.TrimLeft(rest[i+1:], " ")
	}
	if !strings.HasPrefix(rest, "/") {
		return fmt.Errorf("route pattern %q: host patterns are not allowed", p)
	}
	path := patternPath(p)
	if !strings.HasPrefix(path, "/") || path == "/" {
		return fmt.Errorf("invalid route pattern %q", p)
	}
	if p != strings.TrimSpace(p) || strings.ContainsAny(p, "\t\r\n") {
		return fmt.Errorf("invalid route pattern %q", p)
	}
	trimmed := strings.TrimSuffix(strings.TrimSuffix(path, "{$}"), "/")
	for _, core := range server.CorePaths {
		if core == "/" {
			continue
		}
		// Equal paths, or a subtree pattern that would contain a core
		// path (for example "/v1/").
		if trimmed == core || (strings.HasSuffix(path, "/") && strings.HasPrefix(core, path)) {
			return fmt.Errorf("route pattern %q overlaps the core route %s", p, core)
		}
	}
	return nil
}

// mountExtensions calls every extension's Mount and collects routes,
// readiness checks and closers. On error, the closers of extensions that
// were already mounted are called.
func mountExtensions(ctx context.Context, exts []Extension, h Host) (map[string]http.Handler, []func(context.Context) error, []func(), error) {
	routes := map[string]http.Handler{}
	owner := map[string]string{}
	var ready []func(context.Context) error
	var closers []func()
	fail := func(err error) (map[string]http.Handler, []func(context.Context) error, []func(), error) {
		for _, c := range closers {
			c()
		}
		return nil, nil, nil, err
	}
	for _, e := range exts {
		eh := h
		eh.Logger = h.Logger.With("extension", e.Name)
		r, err := e.Mount(ctx, eh)
		if err != nil {
			return fail(fmt.Errorf("extension %s: %w", e.Name, err))
		}
		if e.Close != nil {
			closers = append(closers, e.Close)
		}
		for p, handler := range r {
			if handler == nil {
				return fail(fmt.Errorf("extension %s: route %q has no handler", e.Name, p))
			}
			if err := checkPattern(p); err != nil {
				return fail(fmt.Errorf("extension %s: %w", e.Name, err))
			}
			if o, ok := owner[p]; ok {
				return fail(fmt.Errorf("extension %s: route %q is already used by extension %s", e.Name, p, o))
			}
			owner[p] = e.Name
			routes[p] = handler
		}
		if e.Ready != nil {
			ready = append(ready, e.Ready)
		}
	}
	// Overlapping patterns between extensions (for example "/a/" and
	// "GET /a/b") are legal for ServeMux; truly conflicting ones make it
	// panic. Detect that here instead of at startup.
	if err := tryRegister(routes); err != nil {
		return fail(err)
	}
	return routes, ready, closers, nil
}

func tryRegister(routes map[string]http.Handler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("conflicting extension routes: %v", r)
		}
	}()
	mux := http.NewServeMux()
	for _, c := range server.CorePaths {
		mux.Handle(c, http.NotFoundHandler())
	}
	for p, h := range routes {
		mux.Handle(p, h)
	}
	// Whatever the method, every core path must still be served by the
	// core pattern.
	for _, c := range server.CorePaths {
		if c == "/" {
			continue
		}
		for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
			req, _ := http.NewRequest(m, "http://tenant-pass.internal"+c, nil)
			if _, pat := mux.Handler(req); pat != c {
				return fmt.Errorf("extension route %q shadows the core route %s", pat, c)
			}
		}
	}
	return nil
}
