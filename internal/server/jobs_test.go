package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/ratelimit"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

func jobEnv(t *testing.T) (*env, pass.Signer) {
	t.Helper()
	e := newEnv(t, 60)
	own := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	sched := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	signer := &pass.Signer{KeyID: "tp-jobs", Key: own}
	e.srv.cfg.JobSigner = signer
	e.srv.cfg.JobVerifier = &pass.JobVerifier{Keys: map[string]ed25519.PublicKey{
		"tp-jobs":   own.Public().(ed25519.PublicKey),
		"scheduler": sched.Public().(ed25519.PublicKey),
	}}
	e.srv.cfg.JobPolicies = map[string]JobPolicy{
		"billing": {Issue: true, MaxTTL: 30 * time.Minute, Limiter: ratelimit.NewDistinct(2), Issuers: map[string]bool{"tp-jobs": true, "scheduler": true}},
		"crm":     {MaxTTL: time.Hour, Limiter: ratelimit.NewDistinct(10), Issuers: map[string]bool{"tp-jobs": true}},
	}
	return e, pass.Signer{KeyID: "scheduler", Key: sched}
}

func (e *env) post(t *testing.T, path, token, body string) (int, map[string]string) {
	t.Helper()
	r := strings.NewReader(body)
	req := httptestRequest(path, r)
	req.Header.Set("Authorization", "Bearer "+token)
	w := newRecorder()
	e.h.ServeHTTP(w, req)
	var out map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestJobTicketFlow(t *testing.T) {
	e, _ := jobEnv(t)
	code, out := e.post(t, "/v1/job-tickets", "tpa_billing", `{"pass":"`+e.pass(t, "billing", "acme.example.com")+`","ttl":"2h"}`)
	if code != 200 || out["tenant"] != "acme" || out["ticket"] == "" {
		t.Fatalf("issue: %d %v", code, out)
	}
	// ttl is capped by the application's max_ttl (30m).
	exp, _ := time.Parse(time.RFC3339, out["expires_at"])
	if d := time.Until(exp); d > 30*time.Minute || d < 29*time.Minute {
		t.Errorf("ticket lifetime %v", d)
	}
	code, cred := e.post(t, "/v1/credentials", "tpa_billing", `{"ticket":"`+out["ticket"]+`"}`)
	if code != 200 || cred["username"] != "t_acme" {
		t.Fatalf("redeem: %d %v", code, cred)
	}
	if strings.Contains(e.logs.String(), out["ticket"]) {
		t.Fatal("ticket written to log")
	}
	// Another application cannot redeem it (aud is billing).
	if code, _ := e.post(t, "/v1/credentials", "tpa_crm", `{"ticket":"`+out["ticket"]+`"}`); code != 400 {
		t.Errorf("crm redeem: %d", code)
	}
}

func TestJobTicketRejections(t *testing.T) {
	e, sched := jobEnv(t)
	now := time.Now()
	schedTicket, _ := sched.SignJob(context.Background(), pass.JobClaims{Audience: "billing", Tenant: "acme", IssuedAt: now, Expiry: now.Add(10 * time.Minute)})
	disabled, _ := sched.SignJob(context.Background(), pass.JobClaims{Audience: "billing", Tenant: "off", IssuedAt: now, Expiry: now.Add(10 * time.Minute)})
	forger := pass.Signer{KeyID: "scheduler", Key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))}
	forged, _ := forger.SignJob(context.Background(), pass.JobClaims{Audience: "billing", Tenant: "acme", IssuedAt: now, Expiry: now.Add(10 * time.Minute)})
	p := e.pass(t, "billing", "acme.example.com")
	crmSched, _ := sched.SignJob(context.Background(), pass.JobClaims{Audience: "crm", Tenant: "acme", IssuedAt: now, Expiry: now.Add(10 * time.Minute)})
	long, _ := sched.SignJob(context.Background(), pass.JobClaims{Audience: "billing", Tenant: "acme", IssuedAt: now, Expiry: now.Add(45 * time.Minute)})

	cases := []struct {
		name, path, token, body string
		code                    int
		err                     string
	}{
		{"scheduler ticket ok", "/v1/credentials", "tpa_billing", `{"ticket":"` + schedTicket + `"}`, 200, ""},
		{"forged ticket", "/v1/credentials", "tpa_billing", `{"ticket":"` + forged + `"}`, 400, codeInvalidTicket},
		{"pass as ticket", "/v1/credentials", "tpa_billing", `{"ticket":"` + p + `"}`, 400, codeInvalidTicket},
		{"ticket as pass", "/v1/credentials", "tpa_billing", `{"pass":"` + schedTicket + `"}`, 400, codeInvalidPass},
		{"both", "/v1/credentials", "tpa_billing", `{"pass":"` + p + `","ticket":"` + schedTicket + `"}`, 400, codeInvalidRequest},
		{"disabled tenant", "/v1/credentials", "tpa_billing", `{"ticket":"` + disabled + `"}`, 403, codeDenied},
		{"issuer not allowed for crm", "/v1/credentials", "tpa_crm", `{"ticket":"` + crmSched + `"}`, 403, codeDenied},
		{"lifetime above app max", "/v1/credentials", "tpa_billing", `{"ticket":"` + long + `"}`, 400, codeInvalidTicket},
		{"issue not allowed for crm", "/v1/job-tickets", "tpa_crm", `{"pass":"` + e.pass(t, "crm", "acme.example.com") + `"}`, 403, codeDenied},
		{"issue with ticket", "/v1/job-tickets", "tpa_billing", `{"pass":"` + schedTicket + `"}`, 400, codeInvalidPass},
		{"bad ttl", "/v1/job-tickets", "tpa_billing", `{"pass":"` + p + `","ttl":"10s"}`, 400, codeInvalidRequest},
		{"unknown host", "/v1/job-tickets", "tpa_billing", `{"pass":"` + e.pass(t, "billing", "nope.example.com") + `"}`, 403, codeDenied},
	}
	for _, c := range cases {
		code, out := e.post(t, c.path, c.token, c.body)
		if code != c.code || (c.err != "" && out["error"] != c.err) {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
}

func TestJobLimiterIsSeparate(t *testing.T) {
	e, sched := jobEnv(t)
	now := time.Now()
	for i, tenant := range []string{"acme", "t1", "t2"} {
		tk, _ := sched.SignJob(context.Background(), pass.JobClaims{Audience: "billing", Tenant: tenant, IssuedAt: now, Expiry: now.Add(10 * time.Minute)})
		code, _ := e.post(t, "/v1/credentials", "tpa_billing", `{"ticket":"`+tk+`"}`)
		want := 200
		if i == 2 {
			want = 429 // job limiter allows 2 distinct tenants
		}
		if code != want {
			t.Errorf("tenant %s: %d, want %d", tenant, code, want)
		}
	}
	// Passes still have their own budget.
	if code, _ := e.post(t, "/v1/credentials", "tpa_billing", body(e.pass(t, "billing", "t2.example.com"))); code != 200 {
		t.Errorf("pass after job limit: %d", code)
	}
}
