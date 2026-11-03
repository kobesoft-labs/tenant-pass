package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/config"
	"github.com/kobesoft-labs/tenant-pass/internal/hostname"
	"github.com/kobesoft-labs/tenant-pass/internal/netcfg"
	"github.com/kobesoft-labs/tenant-pass/internal/secret"
	"github.com/kobesoft-labs/tenant-pass/internal/strictjson"
	"github.com/kobesoft-labs/tenant-pass/pass"
)

// File is the tenant-pass-gateway configuration file.
type File struct {
	Listen string           `json:"listen"`
	TLS    config.ServerTLS `json:"tls"`
	// InsecurePlaintextHTTP serves plain HTTP. Allowed without
	// AllowInsecurePlaintext only when Listen is a loopback address (the
	// usual sidecar deployment next to the proxy).
	InsecurePlaintextHTTP  bool `json:"insecure_plaintext_http"`
	AllowInsecurePlaintext bool `json:"allow_insecure_plaintext"`
	// CallerSecretFile, if set, requires every request to carry the
	// header Tenant-Pass-Gateway-Secret with this value, so that only the
	// proxy (not applications on the same network) can obtain passes.
	CallerSecretFile string `json:"caller_secret_file"`

	KMS        config.KMSFile        `json:"kms"`
	SigningKey config.SigningKeyFile `json:"signing_key"`

	Pass     PassSettings     `json:"pass"`
	Request  RequestSettings  `json:"request"`
	Identity IdentitySettings `json:"identity"`
	Routes   []Route          `json:"routes"`
	// Unauthenticated decides what happens when a request has no valid
	// session token: "pass_through" (default) answers 200 without a
	// pass, so the application can show a login page but cannot obtain
	// tenant credentials; "deny" answers 401.
	Unauthenticated string `json:"unauthenticated"`
	LogLevel        string `json:"log_level"`
}

// PassSettings controls the passes the gateway signs.
type PassSettings struct {
	TTL    config.Duration `json:"ttl"`
	Header string          `json:"header"`
}

// RequestSettings says where the original request's host is found.
type RequestSettings struct {
	// HostHeader carries the original host. Default X-Forwarded-Host
	// (Caddy, Traefik, nginx with proxy_set_header). For Envoy ext_authz,
	// use "Host".
	HostHeader string `json:"host_header"`
}

// IdentitySettings configures verification of end-user session tokens
// (JWTs issued by your identity provider).
type IdentitySettings struct {
	Issuer    string   `json:"issuer"`
	Audiences []string `json:"audiences"`
	// Exactly one of JWKSURL and JWKSFile.
	JWKSURL  string     `json:"jwks_url"`
	JWKSFile string     `json:"jwks_file"`
	JWKSTLS  netcfg.TLS `json:"jwks_tls"`
	// Algorithms allowed for token signatures. Default RS256, ES256,
	// EdDSA. Symmetric algorithms (HS*) and "none" are never allowed.
	Algorithms []string `json:"algorithms"`
	// Token sources, tried in order: the Authorization: Bearer header if
	// AuthorizationHeader is true, then the named cookie.
	AuthorizationHeader bool   `json:"authorization_header"`
	Cookie              string `json:"cookie"`
	// TenantClaim is the claim holding the user's tenant ID, or a list of
	// tenant IDs. Dotted paths reach into nested objects ("org.id").
	TenantClaim string          `json:"tenant_claim"`
	Leeway      config.Duration `json:"leeway"`
	// MaxTokenAge rejects tokens whose iat is older than this (0: no
	// limit). Useful with long-lived session tokens.
	MaxTokenAge config.Duration `json:"max_token_age"`
	// RequiredClaims are string claims that must have exactly these
	// values, for example {"typ": "Bearer"} or {"azp": "web-app"}, to
	// reject tokens issued for other purposes or other clients whose
	// audience happens to overlap.
	RequiredClaims map[string]string `json:"required_claims"`
}

// Route maps request hosts to the application that serves them.
type Route struct {
	// Host is an exact canonical host name, or a pattern containing
	// "{tenant}" as one whole label ("{tenant}.app.example.com").
	Host string `json:"host"`
	// App is the application name (the pass's aud).
	App string `json:"app"`
	// Tenant fixes the tenant for an exact host (custom domains).
	Tenant string `json:"tenant"`
	// TenantFromToken takes the tenant from the token for hosts shared by
	// all tenants. The token must then name exactly one tenant.
	TenantFromToken bool `json:"tenant_from_token"`
}

// Defaults.
const (
	DefaultPassTTL    = 30 * time.Second
	DefaultPassHeader = "Tenant-Pass"
	CallerSecretHdr   = "Tenant-Pass-Gateway-Secret"
)

var (
	headerName  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	cookieName  = regexp.MustCompile(`^[A-Za-z0-9_.!#$%&'*+^` + "`" + `|~-]{1,128}$`)
	claimPath   = regexp.MustCompile(`^[A-Za-z0-9_:-]{1,64}(\.[A-Za-z0-9_:-]{1,64}){0,4}$`)
	allowedAlgs = map[string]bool{"RS256": true, "RS384": true, "RS512": true, "PS256": true, "PS384": true, "PS512": true,
		"ES256": true, "ES384": true, "ES512": true, "EdDSA": true}
)

// LoadFile reads and strictly parses a gateway configuration file and
// applies defaults.
func LoadFile(path string) (*File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("config: %s is writable by group or others", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := strictjson.Decode(b, &f); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if f.Listen == "" {
		f.Listen = "127.0.0.1:9180"
	}
	if f.Pass.TTL == 0 {
		f.Pass.TTL = config.Duration(DefaultPassTTL)
	}
	if f.Pass.Header == "" {
		f.Pass.Header = DefaultPassHeader
	}
	if f.Request.HostHeader == "" {
		f.Request.HostHeader = "X-Forwarded-Host"
	}
	if len(f.Identity.Algorithms) == 0 {
		f.Identity.Algorithms = []string{"RS256", "ES256", "EdDSA"}
	}
	if f.Identity.Leeway == 0 {
		f.Identity.Leeway = config.Duration(30 * time.Second)
	}
	if f.Unauthenticated == "" {
		f.Unauthenticated = "pass_through"
	}
	if f.LogLevel == "" {
		f.LogLevel = "info"
	}
	return &f, nil
}

// route is a compiled Route.
type route struct {
	Route
	prefix, suffix string // for {tenant} patterns: host = prefix + label + suffix
	pattern        bool
}

// validate checks the configuration (except keys, which main loads).
func (f *File) validate() ([]route, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if f.InsecurePlaintextHTTP {
		host, _, err := net.SplitHostPort(f.Listen)
		ip := net.ParseIP(host)
		loopback := err == nil && ip != nil && ip.IsLoopback()
		if !loopback && !f.AllowInsecurePlaintext {
			fail("insecure_plaintext_http on a non-loopback address requires allow_insecure_plaintext (testing only)")
		}
		if f.TLS != (config.ServerTLS{}) {
			fail("insecure_plaintext_http cannot be combined with tls")
		}
	} else if f.TLS.CertFile == "" || f.TLS.KeyFile == "" {
		fail("tls.cert_file and tls.key_file are required (or insecure_plaintext_http on loopback)")
	}
	if f.CallerSecretFile != "" {
		if v, err := secret.ReadFile(f.CallerSecretFile); err != nil {
			fail("caller_secret_file: %v", err)
		} else if v.Len() < 16 {
			fail("caller_secret_file must contain at least 16 characters")
		}
	}
	if ttl := time.Duration(f.Pass.TTL); ttl < 5*time.Second || ttl > pass.HardMaxTTL {
		fail("pass.ttl must be between 5s and %s", pass.HardMaxTTL)
	}
	if !headerName.MatchString(f.Pass.Header) || !headerName.MatchString(f.Request.HostHeader) {
		fail("pass.header and request.host_header must be valid header names")
	}

	id := f.Identity
	if u, err := url.Parse(id.Issuer); err != nil || id.Issuer == "" || u.Scheme == "" {
		fail("identity.issuer must be the issuer URL (iss claim)")
	}
	if len(id.Audiences) == 0 {
		fail("identity.audiences is required")
	}
	switch {
	case (id.JWKSURL == "") == (id.JWKSFile == ""):
		fail("identity: exactly one of jwks_url and jwks_file is required")
	case id.JWKSURL != "":
		u, err := url.Parse(id.JWKSURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			fail("identity.jwks_url must be an https URL")
		}
	}
	for _, a := range id.Algorithms {
		if !allowedAlgs[a] {
			fail("identity.algorithms: %q is not allowed (asymmetric algorithms only)", a)
		}
	}
	if !id.AuthorizationHeader && id.Cookie == "" {
		fail("identity: enable authorization_header and/or set cookie")
	}
	if id.Cookie != "" && !cookieName.MatchString(id.Cookie) {
		fail("identity.cookie is not a valid cookie name")
	}
	if !claimPath.MatchString(id.TenantClaim) {
		fail("identity.tenant_claim is required (claim name or dotted path)")
	}
	if id.Leeway < 0 || time.Duration(id.Leeway) > 5*time.Minute {
		fail("identity.leeway must be between 0 and 5m")
	}
	for name := range id.RequiredClaims {
		if !claimPath.MatchString(name) || strings.Contains(name, ".") {
			fail("identity.required_claims: invalid claim name %q", name)
		}
	}
	if id.MaxTokenAge < 0 {
		fail("identity.max_token_age must not be negative")
	}

	switch f.Unauthenticated {
	case "pass_through", "deny":
	default:
		fail(`unauthenticated must be "pass_through" or "deny"`)
	}

	var routes []route
	seen := map[string]bool{}
	if len(f.Routes) == 0 {
		fail("at least one route is required")
	}
	for _, r := range f.Routes {
		if !pass.NamePattern.MatchString(r.App) {
			fail("route %q: invalid app", r.Host)
			continue
		}
		if seen[r.Host] {
			fail("route %q is duplicated", r.Host)
			continue
		}
		seen[r.Host] = true
		cr := route{Route: r}
		n := strings.Count(r.Host, "{tenant}")
		switch {
		case n == 1:
			if r.Tenant != "" || r.TenantFromToken {
				fail("route %q: a {tenant} pattern cannot also set tenant or tenant_from_token", r.Host)
				continue
			}
			i := strings.Index(r.Host, "{tenant}")
			cr.prefix, cr.suffix, cr.pattern = r.Host[:i], r.Host[i+len("{tenant}"):], true
			// {tenant} must be a whole label, and the rest must be a
			// valid host name when a label is substituted.
			if (cr.prefix != "" && !strings.HasSuffix(cr.prefix, ".")) || !strings.HasPrefix(cr.suffix, ".") ||
				!isCanonical(cr.prefix+"x"+cr.suffix) {
				fail("route %q: {tenant} must be a whole label of a valid host name", r.Host)
				continue
			}
		case n == 0:
			if !isCanonical(r.Host) {
				fail("route %q: not a canonical host name", r.Host)
				continue
			}
			if (r.Tenant == "") == !r.TenantFromToken {
				fail("route %q: set exactly one of tenant and tenant_from_token", r.Host)
				continue
			}
			if r.Tenant != "" && !pass.TenantIDPattern.MatchString(r.Tenant) {
				fail("route %q: invalid tenant", r.Host)
				continue
			}
		default:
			fail("route %q: at most one {tenant}", r.Host)
			continue
		}
		routes = append(routes, cr)
	}
	switch f.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		fail("log_level must be debug, info, warn or error")
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return routes, nil
}

func isCanonical(h string) bool { return hostname.IsCanonical(h) }
