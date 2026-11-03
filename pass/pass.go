// Package pass creates and verifies tenant-pass "passes".
//
// A pass is a short-lived statement, signed by a trusted gateway, that
// says: "I am forwarding a request for tenant T (identified by host name
// or tenant ID) to application A, right now." An application presents the
// pass to the tenant-pass server together with its own credentials, and
// receives a short-lived credential for tenant T only.
//
// Because the application never holds the gateway's signing key, a
// compromised application cannot mint passes for arbitrary tenants; it can
// only use passes for requests the gateway actually forwarded to it.
//
// # Wire format
//
// A pass is a PASETO v4.public token (Ed25519):
//
//		v4.public.<base64url(claims || signature)>.<base64url(footer)>
//
//	  - The implicit assertion is the fixed string "tenant-pass/v1/pass".
//	    It is signed but never transmitted, so a token produced by the same
//	    key for any other purpose can never be mistaken for a pass.
//	  - The footer is the JSON object {"kid":"<gateway key ID>"} and is
//	    required. It selects which configured gateway public key verifies
//	    the token, which makes key rotation possible.
//	  - The claims are a JSON object with exactly these members:
//
//	    aud     application name the request is forwarded to (required)
//	    host    canonical host name of the request   (exactly one of
//	    tenant  tenant ID, if the gateway knows it    host / tenant)
//	    iat     issued-at time, RFC 3339 UTC, whole seconds (required)
//	    exp     expiry time, RFC 3339 UTC, whole seconds (required)
//	    jti     random identifier, 16-128 chars of [A-Za-z0-9_-] (required)
//
//	    Unknown members and duplicate members are rejected.
//
// The full specification, with test vectors, is in docs/en/pass-format.md.
package pass

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/hostname"
	"github.com/kobesoft-labs/tenant-pass/internal/kms"
	"github.com/kobesoft-labs/tenant-pass/internal/paseto"
	"github.com/kobesoft-labs/tenant-pass/internal/strictjson"
)

// ImplicitAssertion is the PASETO implicit assertion bound into every
// pass signature (domain separation).
const ImplicitAssertion = "tenant-pass/v1/pass"

// MaxLength is the largest pass, in bytes, that Verify will process.
const MaxLength = 2048

// Limits on how long a pass may live. A pass authorizes credential
// issuance for one tenant, so it should be valid only for as long as it
// takes the application to call tenant-pass while handling the request.
const (
	// DefaultMaxTTL is the default upper bound on exp - iat.
	DefaultMaxTTL = 60 * time.Second
	// HardMaxTTL is the largest MaxTTL a Verifier accepts.
	HardMaxTTL = 5 * time.Minute
	// DefaultLeeway tolerates small clock differences between the
	// gateway and tenant-pass when checking iat.
	DefaultLeeway = 5 * time.Second
)

var (
	// NamePattern constrains application names, key IDs and similar
	// identifiers. They appear in logs and configuration, so they are
	// kept boring.
	NamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	// TenantIDPattern constrains tenant IDs.
	TenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	jtiPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// Errors returned by Verify, grouped so that callers can log a reason
// without exposing it to clients. Use errors.Is.
var (
	ErrMalformed  = errors.New("pass: malformed")         // not a well-formed pass
	ErrUnknownKey = errors.New("pass: unknown key")       // kid not configured
	ErrSignature  = errors.New("pass: bad signature")     // signature does not verify
	ErrClaims     = errors.New("pass: invalid claims")    // claims violate the schema
	ErrExpired    = errors.New("pass: expired")           // exp in the past / iat in the future
	ErrAudience   = errors.New("pass: audience mismatch") // aud is not the caller
)

// Claims is the content of a pass.
type Claims struct {
	Audience string    // application name
	Host     string    // canonical host name; empty if Tenant is set
	Tenant   string    // tenant ID; empty if Host is set
	IssuedAt time.Time // whole seconds, UTC
	Expiry   time.Time // whole seconds, UTC
	ID       string    // jti
}

// wireClaims is the exact JSON shape of the claims.
type wireClaims struct {
	Aud    string `json:"aud"`
	Host   string `json:"host,omitempty"`
	Tenant string `json:"tenant,omitempty"`
	Iat    string `json:"iat"`
	Exp    string `json:"exp"`
	Jti    string `json:"jti"`
}

type footer struct {
	Kid string `json:"kid"`
}

// timeLayout is RFC 3339 restricted to UTC ("Z") and whole seconds, so
// each instant has exactly one textual form.
const timeLayout = "2006-01-02T15:04:05Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil || formatTime(t) != s {
		return time.Time{}, ErrClaims
	}
	return t, nil
}

// validate checks the claim schema (not time or audience).
func (c *Claims) validate() error {
	if !NamePattern.MatchString(c.Audience) {
		return fmt.Errorf("%w: aud", ErrClaims)
	}
	switch {
	case c.Host != "" && c.Tenant != "":
		return fmt.Errorf("%w: both host and tenant", ErrClaims)
	case c.Host != "":
		if !hostname.IsCanonical(c.Host) {
			return fmt.Errorf("%w: host not canonical", ErrClaims)
		}
	case c.Tenant != "":
		if !TenantIDPattern.MatchString(c.Tenant) {
			return fmt.Errorf("%w: tenant", ErrClaims)
		}
	default:
		return fmt.Errorf("%w: neither host nor tenant", ErrClaims)
	}
	if !jtiPattern.MatchString(c.ID) {
		return fmt.Errorf("%w: jti", ErrClaims)
	}
	if !c.Expiry.After(c.IssuedAt) {
		return fmt.Errorf("%w: exp not after iat", ErrClaims)
	}
	return nil
}

// NewID returns a random jti (128 bits, base64url).
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms; if it does,
		// continuing would produce predictable IDs.
		panic("pass: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Signer creates passes (and, via SignJob, job tickets).
//
// Set either Key (a local private key) or Remote (a signing function
// backed by a key management system such as Vault Transit).
type Signer struct {
	KeyID string
	Key   ed25519.PrivateKey
	// Remote signs msg with an Ed25519 key held elsewhere. It must return
	// a 64-byte signature.
	Remote func(ctx context.Context, msg []byte) ([]byte, error)
}

func (s Signer) sign(ctx context.Context, m []byte, assertion string) (string, error) {
	if !NamePattern.MatchString(s.KeyID) {
		return "", errors.New("pass: invalid key ID")
	}
	f, err := json.Marshal(footer{Kid: s.KeyID})
	if err != nil {
		return "", err
	}
	switch {
	case s.Remote != nil && s.Key == nil:
		return paseto.SignWith(func(msg []byte) ([]byte, error) { return s.Remote(ctx, msg) }, m, f, []byte(assertion))
	case s.Remote == nil && len(s.Key) == ed25519.PrivateKeySize:
		return paseto.Sign(s.Key, m, f, []byte(assertion))
	default:
		return "", errors.New("pass: set exactly one of Key and Remote")
	}
}

// Sign returns a signed pass for c. IssuedAt and Expiry are truncated to
// whole seconds. If c.ID is empty a random one is generated.
func (s Signer) Sign(c Claims) (string, error) {
	return s.SignContext(context.Background(), c)
}

// SignContext is Sign with a context for remote signers.
func (s Signer) SignContext(ctx context.Context, c Claims) (string, error) {
	c.IssuedAt = c.IssuedAt.UTC().Truncate(time.Second)
	c.Expiry = c.Expiry.UTC().Truncate(time.Second)
	if c.ID == "" {
		c.ID = NewID()
	}
	if err := c.validate(); err != nil {
		return "", err
	}
	m, err := json.Marshal(wireClaims{
		Aud: c.Audience, Host: c.Host, Tenant: c.Tenant,
		Iat: formatTime(c.IssuedAt), Exp: formatTime(c.Expiry), Jti: c.ID,
	})
	if err != nil {
		return "", err
	}
	return s.sign(ctx, m, ImplicitAssertion)
}

// verifyToken performs the checks shared by passes and job tickets:
// length, footer, key lookup by kid, and signature under the given
// implicit assertion. It returns the authenticated message and the key
// ID. Nothing derived from unauthenticated data is used, except the key
// ID to select a key.
func verifyToken(token, assertion string, keys map[string]ed25519.PublicKey) ([]byte, string, error) {
	if len(token) > MaxLength {
		return nil, "", ErrMalformed
	}
	rawFooter, err := paseto.Footer(token)
	if err != nil || len(rawFooter) == 0 || len(rawFooter) > 256 {
		return nil, "", ErrMalformed
	}
	var f footer
	if err := strictjson.Decode(rawFooter, &f); err != nil || !NamePattern.MatchString(f.Kid) {
		return nil, "", ErrMalformed
	}
	key, ok := keys[f.Kid]
	if !ok {
		return nil, "", ErrUnknownKey
	}
	// Small-order or non-canonical public keys accept forged signatures
	// (Go's ed25519.Verify does not reject them). Callers of this package
	// may build key maps themselves, so check here too.
	if !keyIsSafe(key) {
		return nil, "", ErrUnknownKey
	}
	m, _, err := paseto.Verify(key, token, []byte(assertion))
	switch {
	case errors.Is(err, paseto.ErrSignature):
		return nil, "", ErrSignature
	case err != nil:
		return nil, "", ErrMalformed
	}
	return m, f.Kid, nil
}

var safeKeys sync.Map // string(key) -> bool

func keyIsSafe(k ed25519.PublicKey) bool {
	if v, ok := safeKeys.Load(string(k)); ok {
		return v.(bool)
	}
	ok := kms.CheckEd25519PublicKey(k) == nil
	safeKeys.Store(string(k), ok)
	return ok
}

// checkTimes applies the lifetime and time-window rules.
func checkTimes(iat, exp time.Time, maxTTL, hardMax, defMax, leeway time.Duration, now func() time.Time) error {
	if maxTTL <= 0 {
		maxTTL = defMax
	}
	if maxTTL > hardMax {
		maxTTL = hardMax
	}
	switch {
	case leeway == 0:
		leeway = DefaultLeeway
	case leeway < 0:
		leeway = 0
	}
	if exp.Sub(iat) > maxTTL {
		return fmt.Errorf("%w: lifetime too long", ErrClaims)
	}
	if now == nil {
		now = time.Now
	}
	t := now()
	if !t.Before(exp) || iat.After(t.Add(leeway)) {
		return ErrExpired
	}
	return nil
}

// Verifier verifies passes. The zero value is not usable; set Keys.
type Verifier struct {
	// Keys maps gateway key IDs to Ed25519 public keys.
	Keys map[string]ed25519.PublicKey
	// MaxTTL is the largest permitted exp - iat (0 means DefaultMaxTTL).
	MaxTTL time.Duration
	// Leeway is the tolerated clock difference for iat (0 means
	// DefaultLeeway; a negative value means no leeway). It is never
	// applied to exp: an expired pass is expired.
	Leeway time.Duration
	// Now returns the current time (nil means time.Now). For tests.
	Now func() time.Time
}

// Verify checks pass p and returns its claims if, and only if:
//
//   - it is a well-formed v4.public token no longer than MaxLength,
//   - its footer names a configured key and the signature verifies under
//     that key with the tenant-pass implicit assertion,
//   - the claims match the schema exactly,
//   - aud equals audience (the authenticated caller),
//   - iat <= now + Leeway, now < exp, and exp - iat <= MaxTTL.
func (v *Verifier) Verify(p, audience string) (Claims, error) {
	m, _, err := verifyToken(p, ImplicitAssertion, v.Keys)
	if err != nil {
		return Claims{}, err
	}
	var w wireClaims
	if err := strictjson.Decode(m, &w); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrClaims, err)
	}
	c := Claims{Audience: w.Aud, Host: w.Host, Tenant: w.Tenant, ID: w.Jti}
	if c.IssuedAt, err = parseTime(w.Iat); err != nil {
		return Claims{}, fmt.Errorf("%w: iat", ErrClaims)
	}
	if c.Expiry, err = parseTime(w.Exp); err != nil {
		return Claims{}, fmt.Errorf("%w: exp", ErrClaims)
	}
	if err := c.validate(); err != nil {
		return Claims{}, err
	}
	if err := checkTimes(c.IssuedAt, c.Expiry, v.MaxTTL, HardMaxTTL, DefaultMaxTTL, v.Leeway, v.Now); err != nil {
		return Claims{}, err
	}
	// Audience is checked last so that a pass for another application is
	// only reported as such once it is known to be genuine.
	if c.Audience != audience {
		return Claims{}, ErrAudience
	}
	return c, nil
}
