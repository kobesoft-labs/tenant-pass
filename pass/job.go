package pass

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kobesoft-labs/tenant-pass/internal/strictjson"
)

// Job tickets
//
// A pass lives for seconds, because it is tied to one request. Work that
// runs later, outside any request (a queued job, a scheduled report, a
// migration), needs a longer-lived authorization for one tenant. That is
// a job ticket:
//
//	v4.public.<base64url(claims || signature)>.<base64url({"kid":"..."})>
//
// with the implicit assertion "tenant-pass/v1/job" (so a pass can never
// be used as a ticket or vice versa) and exactly these claims:
//
//	aud     application allowed to redeem the ticket
//	tenant  tenant ID (tickets always name the tenant, never a host)
//	iat     issued at, RFC 3339 UTC, whole seconds
//	exp     expiry, same format; exp - iat <= max TTL (at most 24h)
//	jti     random identifier
//
// Tickets are signed either by tenant-pass itself (POST /v1/job-tickets,
// in exchange for a pass while handling a request) or by a trusted
// external issuer such as a scheduler that the operator runs.

// JobImplicitAssertion is the implicit assertion of job tickets.
const JobImplicitAssertion = "tenant-pass/v1/job"

// Job ticket lifetime limits.
const (
	DefaultJobMaxTTL = time.Hour
	HardJobMaxTTL    = 24 * time.Hour
)

// JobClaims is the content of a job ticket.
type JobClaims struct {
	Audience string
	Tenant   string
	IssuedAt time.Time
	Expiry   time.Time
	ID       string
}

type wireJobClaims struct {
	Aud    string `json:"aud"`
	Tenant string `json:"tenant"`
	Iat    string `json:"iat"`
	Exp    string `json:"exp"`
	Jti    string `json:"jti"`
}

func (c *JobClaims) validate() error {
	if !NamePattern.MatchString(c.Audience) {
		return fmt.Errorf("%w: aud", ErrClaims)
	}
	if !TenantIDPattern.MatchString(c.Tenant) {
		return fmt.Errorf("%w: tenant", ErrClaims)
	}
	if !jtiPattern.MatchString(c.ID) {
		return fmt.Errorf("%w: jti", ErrClaims)
	}
	if !c.Expiry.After(c.IssuedAt) {
		return fmt.Errorf("%w: exp not after iat", ErrClaims)
	}
	return nil
}

// SignJob returns a signed job ticket for c.
func (s Signer) SignJob(ctx context.Context, c JobClaims) (string, error) {
	c.IssuedAt = c.IssuedAt.UTC().Truncate(time.Second)
	c.Expiry = c.Expiry.UTC().Truncate(time.Second)
	if c.ID == "" {
		c.ID = NewID()
	}
	if err := c.validate(); err != nil {
		return "", err
	}
	if c.Expiry.Sub(c.IssuedAt) > HardJobMaxTTL {
		return "", fmt.Errorf("%w: lifetime too long", ErrClaims)
	}
	m, err := json.Marshal(wireJobClaims{
		Aud: c.Audience, Tenant: c.Tenant,
		Iat: formatTime(c.IssuedAt), Exp: formatTime(c.Expiry), Jti: c.ID,
	})
	if err != nil {
		return "", err
	}
	return s.sign(ctx, m, JobImplicitAssertion)
}

// JobVerifier verifies job tickets.
type JobVerifier struct {
	// Keys maps issuer key IDs (tenant-pass's own job key and trusted
	// external issuers) to Ed25519 public keys.
	Keys   map[string]ed25519.PublicKey
	MaxTTL time.Duration // 0 means DefaultJobMaxTTL; capped at HardJobMaxTTL
	Leeway time.Duration
	Now    func() time.Time
}

// Verify checks ticket t for the authenticated application audience and
// returns its claims and the ID of the key that signed it. The rules are
// the same as for passes, with the job implicit assertion, the job claim
// schema and the job lifetime limits.
func (v *JobVerifier) Verify(t, audience string) (JobClaims, string, error) {
	m, kid, err := verifyToken(t, JobImplicitAssertion, v.Keys)
	if err != nil {
		return JobClaims{}, "", err
	}
	var w wireJobClaims
	if err := strictjson.Decode(m, &w); err != nil {
		return JobClaims{}, "", fmt.Errorf("%w: %v", ErrClaims, err)
	}
	c := JobClaims{Audience: w.Aud, Tenant: w.Tenant, ID: w.Jti}
	if c.IssuedAt, err = parseTime(w.Iat); err != nil {
		return JobClaims{}, "", fmt.Errorf("%w: iat", ErrClaims)
	}
	if c.Expiry, err = parseTime(w.Exp); err != nil {
		return JobClaims{}, "", fmt.Errorf("%w: exp", ErrClaims)
	}
	if err := c.validate(); err != nil {
		return JobClaims{}, "", err
	}
	if err := checkTimes(c.IssuedAt, c.Expiry, v.MaxTTL, HardJobMaxTTL, DefaultJobMaxTTL, v.Leeway, v.Now); err != nil {
		return JobClaims{}, "", err
	}
	if c.Audience != audience {
		return JobClaims{}, "", ErrAudience
	}
	return c, kid, nil
}
