package tenantpass

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }

func host() Host { return Host{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))} }

func TestCheckPattern(t *testing.T) {
	good := []string{"POST /v1/storage", "/v1/storage/public", "GET /x/{id}", "POST example.internal/v1/ticket"}
	for _, p := range good {
		if err := checkPattern(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	bad := []string{
		"/", "GET /", "POST /v1/credentials", "/v1/credentials", "/v1/credentials/",
		"GET /healthz", "/readyz", "/v1/job-tickets", "/v1/", " /x", "x",
	}
	for _, p := range bad {
		if err := checkPattern(p); err == nil {
			t.Errorf("%q: accepted", p)
		}
	}
}

func TestMountExtensions(t *testing.T) {
	closed := 0
	ext := func(name string, routes map[string]http.Handler) Extension {
		return Extension{
			Name:  name,
			Mount: func(context.Context, Host) (map[string]http.Handler, error) { return routes, nil },
			Close: func() { closed++ },
		}
	}
	routes, ready, closers, err := mountExtensions(context.Background(), []Extension{
		ext("a", map[string]http.Handler{"POST /v1/storage": http.HandlerFunc(ok)}),
		ext("b", map[string]http.Handler{"POST /v1/ticket": http.HandlerFunc(ok)}),
	}, host())
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || len(ready) != 0 || len(closers) != 2 {
		t.Fatalf("routes=%d ready=%d closers=%d", len(routes), len(ready), len(closers))
	}

	// Duplicate route across extensions: rejected, and the first
	// extension's Close runs.
	closed = 0
	_, _, _, err = mountExtensions(context.Background(), []Extension{
		ext("a", map[string]http.Handler{"POST /v1/storage": http.HandlerFunc(ok)}),
		ext("b", map[string]http.Handler{"POST /v1/storage": http.HandlerFunc(ok)}),
	}, host())
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("err = %v", err)
	}
	if closed != 2 {
		t.Fatalf("closed = %d, want 2", closed)
	}

	// Core path: rejected.
	_, _, _, err = mountExtensions(context.Background(), []Extension{
		ext("a", map[string]http.Handler{"POST /v1/credentials": http.HandlerFunc(ok)}),
	}, host())
	if err == nil {
		t.Fatal("core path accepted")
	}

	// Mount error is returned with the extension's name.
	_, _, _, err = mountExtensions(context.Background(), []Extension{{
		Name:  "broken",
		Mount: func(context.Context, Host) (map[string]http.Handler, error) { return nil, errors.New("boom") },
	}}, host())
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("err = %v", err)
	}

	// Conflicting patterns between extensions (ServeMux would panic).
	_, _, _, err = mountExtensions(context.Background(), []Extension{
		ext("a", map[string]http.Handler{"GET /x/{a}": http.HandlerFunc(ok)}),
		ext("b", map[string]http.Handler{"GET /x/{b}": http.HandlerFunc(ok)}),
	}, host())
	if err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("err = %v", err)
	}
}

func TestOptionsValidate(t *testing.T) {
	m := func(context.Context, Host) (map[string]http.Handler, error) { return nil, nil }
	cases := []struct {
		o    Options
		fail bool
	}{
		{Options{}, true},
		{Options{ConfigPath: "c.json"}, false},
		{Options{ConfigPath: "c.json", Extensions: []Extension{{Name: "appz", Mount: m}}}, false},
		{Options{ConfigPath: "c.json", Extensions: []Extension{{Name: "Appz", Mount: m}}}, true},
		{Options{ConfigPath: "c.json", Extensions: []Extension{{Name: "a", Mount: m}, {Name: "a", Mount: m}}}, true},
		{Options{ConfigPath: "c.json", Extensions: []Extension{{Name: "a"}}}, true},
	}
	for i, c := range cases {
		if err := c.o.validate(); (err != nil) != c.fail {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}
