package directory

import (
	"context"
	"errors"
	"testing"
)

func TestStatic(t *testing.T) {
	d, err := NewStatic([]StaticTenant{
		{ID: "acme", Hosts: []string{"acme.example.com"}, Node: "pg1", Account: "t_acme", Enabled: true, Apps: []string{"billing"}},
		{ID: "beta", Hosts: []string{"beta.example.com"}, Node: "pg1", Account: "t_beta", Enabled: false, Apps: []string{"billing", "crm"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, err := d.ByHost(ctx, "acme.example.com", "billing")
	if err != nil || got.Account != "t_acme" || !got.Enabled {
		t.Fatalf("ByHost = %+v %v", got, err)
	}
	if _, err := d.ByHost(ctx, "acme.example.com", "crm"); !errors.Is(err, ErrNotFound) {
		t.Errorf("app not allowed: %v", err)
	}
	if _, err := d.ByHost(ctx, "nope.example.com", "billing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown host: %v", err)
	}
	if got, err := d.ByTenant(ctx, "beta", "crm"); err != nil || got.Enabled {
		t.Errorf("ByTenant = %+v %v", got, err)
	}
}

func TestStaticValidation(t *testing.T) {
	bad := [][]StaticTenant{
		{{ID: "a", Node: "pg1", Account: "t_a"}}, // no apps
		{{ID: "a", Node: "pg1", Account: "t_a", Apps: []string{"x"}}, {ID: "a", Node: "pg1", Account: "t_b", Apps: []string{"x"}}},
		{{ID: "a", Hosts: []string{"h.example"}, Node: "pg1", Account: "t_a", Apps: []string{"x"}}, {ID: "b", Hosts: []string{"h.example"}, Node: "pg1", Account: "t_b", Apps: []string{"x"}}},
		{{ID: "../a", Node: "pg1", Account: "t_a", Apps: []string{"x"}}},
		{{ID: "a", Node: "PG 1", Account: "t_a", Apps: []string{"x"}}},
		{{ID: "a", Node: "pg1", Account: "", Apps: []string{"x"}}},
	}
	for i, ts := range bad {
		if _, err := NewStatic(ts); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
