package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	a, err := New([]App{
		{Name: "billing", TokenSHA256: HashToken("tpa_billing")},
		{Name: "crm", TokenSHA256: HashToken("tpa_crm"), ClientCertURI: "spiffe://example.org/crm"},
		{Name: "batch", ClientCertURI: "spiffe://example.org/batch"},
		{Name: "batch2", ClientCertURI: "spiffe://example.org/batch2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		authz []string
		uris  []string
		want  string
	}{
		{"token", []string{"Bearer tpa_billing"}, nil, "billing"},
		{"scheme case", []string{"bearer tpa_billing"}, nil, "billing"},
		{"wrong token", []string{"Bearer tpa_nope"}, nil, ""},
		{"no auth", nil, nil, ""},
		{"basic", []string{"Basic dXNlcjpwYXNz"}, nil, ""},
		{"two headers", []string{"Bearer tpa_billing", "Bearer tpa_billing"}, nil, ""},
		{"empty token", []string{"Bearer "}, nil, ""},
		{"token+cert", []string{"Bearer tpa_crm"}, []string{"spiffe://example.org/crm"}, "crm"},
		{"token without cert", []string{"Bearer tpa_crm"}, nil, ""},
		{"token with wrong cert", []string{"Bearer tpa_crm"}, []string{"spiffe://example.org/batch"}, ""},
		{"cert only", nil, []string{"spiffe://example.org/batch"}, "batch"},
		{"cert of token app", nil, []string{"spiffe://example.org/crm"}, ""},
		{"cert naming two cert-only apps", nil, []string{"spiffe://example.org/batch", "spiffe://example.org/batch2"}, ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/v1/credentials", nil)
		for _, h := range c.authz {
			r.Header.Add("Authorization", h)
		}
		if c.uris != nil {
			cert := &x509.Certificate{}
			for _, u := range c.uris {
				pu, _ := url.Parse(u)
				cert.URIs = append(cert.URIs, pu)
			}
			r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
		}
		got, err := a.Authenticate(r)
		if got != c.want || (c.want == "") != (err != nil) {
			t.Errorf("%s: got %q %v, want %q", c.name, got, err, c.want)
		}
	}
}

// Unverified peer certificates (r.TLS.PeerCertificates without
// VerifiedChains) must never count.
func TestUnverifiedCertIgnored(t *testing.T) {
	a, _ := New([]App{{Name: "batch", ClientCertURI: "spiffe://example.org/batch"}})
	r := httptest.NewRequest("POST", "/", nil)
	pu, _ := url.Parse("spiffe://example.org/batch")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{pu}}}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatal("unverified certificate accepted")
	}
}

func TestNewValidation(t *testing.T) {
	bad := [][]App{
		{{Name: "a"}},
		{{Name: "a", TokenSHA256: []byte("short")}},
		{{Name: "a", TokenSHA256: HashToken("x")}, {Name: "a", TokenSHA256: HashToken("y")}},
		{{Name: "a", TokenSHA256: HashToken("x")}, {Name: "b", TokenSHA256: HashToken("x")}},
		{{Name: "a", ClientCertURI: "u"}, {Name: "b", ClientCertURI: "u"}},
	}
	for i, apps := range bad {
		if _, err := New(apps); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
